package mock

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

// ErrFrameTooLarge reports that the proxy bounded an unterminated provider
// frame before relaying enough bytes for the real client to reject it.
var ErrFrameTooLarge = errors.New("mock boundary frame exceeds protocol limit")

// Gateway is a frame-aware byte proxy between a real provider client and an
// external provider transport. It applies faults to complete NDJSON frames but
// deliberately does not decode or implement JSON-RPC.
type Gateway struct {
	upstream io.ReadWriteCloser
	faults   *Faults

	ctx    context.Context
	cancel context.CancelFunc

	responseReader *io.PipeReader
	responseWriter *io.PipeWriter
	writeMu        sync.Mutex
	writeBuffer    []byte

	closeOnce sync.Once
	wait      sync.WaitGroup
	done      chan struct{}
	errMu     sync.Mutex
	err       error
}

// NewGateway starts a proxy over an owned full-duplex provider transport.
func NewGateway(upstream io.ReadWriteCloser, faults *Faults) (*Gateway, error) {
	if upstream == nil {
		return nil, fmt.Errorf("mock gateway upstream is required")
	}
	ctx, cancel := context.WithCancel(context.Background()) // #nosec G118 -- Gateway retains cancel and invokes it exactly once from terminate.
	responseReader, responseWriter := io.Pipe()
	gateway := &Gateway{
		upstream:       upstream,
		faults:         faults,
		ctx:            ctx,
		cancel:         cancel,
		responseReader: responseReader,
		responseWriter: responseWriter,
		done:           make(chan struct{}),
	}
	gateway.wait.Add(1)
	go gateway.pump(PointProviderToGateway, upstream, responseWriter)
	go func() {
		gateway.wait.Wait()
		close(gateway.done)
	}()
	return gateway, nil
}

// Client constructs the real public SDK client over this fault boundary.
func (g *Gateway) Client(options ...provider.Option) (*provider.Client, error) {
	if g == nil {
		return nil, fmt.Errorf("mock gateway is required")
	}
	return provider.NewClient(g, g, options...)
}

// Read exposes provider-to-gateway bytes to a real provider client.
func (g *Gateway) Read(data []byte) (int, error) {
	if g == nil || g.responseReader == nil {
		return 0, io.ErrClosedPipe
	}
	return g.responseReader.Read(data)
}

// Write accepts gateway-to-provider bytes from a real provider client.
func (g *Gateway) Write(data []byte) (int, error) {
	if g == nil {
		return 0, io.ErrClosedPipe
	}
	if len(data) == 0 {
		return 0, nil
	}
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if g.ctx.Err() != nil {
		return 0, g.boundaryError()
	}
	written := len(data)
	for len(data) > 0 {
		separator := bytes.IndexByte(data, '\n')
		if separator < 0 {
			if len(data) > protocol.MaxMessageBytes-len(g.writeBuffer) {
				g.writeBuffer = nil
				g.terminate(ErrFrameTooLarge)
				return 0, ErrFrameTooLarge
			}
			g.writeBuffer = append(g.writeBuffer, data...)
			break
		}
		if separator > protocol.MaxMessageBytes-len(g.writeBuffer) {
			g.writeBuffer = nil
			g.terminate(ErrFrameTooLarge)
			return 0, ErrFrameTooLarge
		}
		frame := make([]byte, 0, len(g.writeBuffer)+separator)
		frame = append(frame, g.writeBuffer...)
		frame = append(frame, data[:separator]...)
		g.writeBuffer = nil
		if err := g.forward(PointGatewayToProvider, g.upstream, frame); err != nil {
			g.terminate(err)
			return 0, err
		}
		data = data[separator+1:]
	}
	return written, nil
}

// Disconnect closes the byte boundary with an observable disconnect fault.
func (g *Gateway) Disconnect() error {
	if g == nil {
		return nil
	}
	g.terminate(ErrDisconnected)
	return nil
}

// Wait waits for both forwarding directions and returns the boundary failure.
func (g *Gateway) Wait(ctx context.Context) error {
	if g == nil || ctx == nil {
		return fmt.Errorf("mock gateway and context are required")
	}
	select {
	case <-g.done:
		g.errMu.Lock()
		defer g.errMu.Unlock()
		return g.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close releases the proxy and its owned upstream transport.
func (g *Gateway) Close() error {
	if g == nil {
		return nil
	}
	g.terminate(nil)
	return nil
}

func (g *Gateway) pump(point FaultPoint, source io.Reader, destination io.Writer) {
	defer g.wait.Done()
	reader := bufio.NewReaderSize(source, 64<<10)
	for {
		frame, terminated, err := readBoundaryFrame(reader)
		if terminated {
			if forwardErr := g.forward(point, destination, frame); forwardErr != nil {
				g.terminate(forwardErr)
				return
			}
		}
		if err != nil {
			for _, pending := range g.faults.Flush(point) {
				if writeErr := writeBoundaryFrame(destination, pending); writeErr != nil {
					g.terminate(writeErr)
					return
				}
			}
			if !terminated && len(frame) > 0 {
				if writeErr := writeAll(destination, frame); writeErr != nil {
					g.terminate(writeErr)
					return
				}
			}
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) && g.ctx.Err() == nil {
				g.terminate(err)
			} else {
				g.terminate(nil)
			}
			return
		}
	}
}

func readBoundaryFrame(reader *bufio.Reader) ([]byte, bool, error) {
	maximum := protocol.MaxMessageBytes + 1
	frame := make([]byte, 0, 64<<10)
	for {
		fragment, err := reader.ReadSlice('\n')
		terminated := err == nil
		payload := fragment
		if terminated {
			payload = fragment[:len(fragment)-1]
		}
		remaining := maximum - len(frame)
		if len(payload) > remaining {
			frame = append(frame, payload[:remaining]...)
			return frame, true, ErrFrameTooLarge
		}
		frame = append(frame, payload...)
		switch {
		case terminated:
			return frame, true, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return frame, false, io.EOF
		default:
			return frame, false, err
		}
	}
}

func (g *Gateway) forward(point FaultPoint, destination io.Writer, payload []byte) error {
	frames, err := g.faults.Apply(g.ctx, point, payload)
	if err != nil {
		if errors.Is(err, ErrCrash) {
			if crasher, ok := g.upstream.(interface{ Crash() error }); ok {
				_ = crasher.Crash()
			}
		}
		return err
	}
	for _, frame := range frames {
		if err := writeBoundaryFrame(destination, frame); err != nil {
			return err
		}
	}
	return nil
}

func (g *Gateway) terminate(err error) {
	g.closeOnce.Do(func() {
		g.errMu.Lock()
		g.err = err
		g.errMu.Unlock()
		g.cancel()
		_ = g.responseWriter.CloseWithError(err)
		if closeErr := g.upstream.Close(); err == nil && closeErr != nil {
			g.errMu.Lock()
			g.err = closeErr
			g.errMu.Unlock()
		}
	})
}

func (g *Gateway) boundaryError() error {
	g.errMu.Lock()
	defer g.errMu.Unlock()
	if g.err != nil {
		return g.err
	}
	return io.ErrClosedPipe
}

func writeBoundaryFrame(destination io.Writer, payload []byte) error {
	frame := make([]byte, len(payload)+1)
	copy(frame, payload)
	frame[len(payload)] = '\n'
	return writeAll(destination, frame)
}

func writeAll(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := destination.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
