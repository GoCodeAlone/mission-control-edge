package mock

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// ProviderConfig describes one external provider process. Path is executed
// directly; Args are never interpreted by a shell. Env is appended to the
// inherited environment. Stderr defaults to io.Discard so provider content is
// not retained accidentally by the conformance harness.
type ProviderConfig struct {
	Path   string
	Args   []string
	Env    []string
	Dir    string
	Stderr io.Writer
}

// Provider owns an external provider's stdio and process lifecycle.
type Provider struct {
	command *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser

	done chan struct{}
	mu   sync.Mutex
	err  error
}

// StartProvider launches an external provider without a shell.
func StartProvider(ctx context.Context, config ProviderConfig) (*Provider, error) {
	if ctx == nil {
		return nil, fmt.Errorf("mock provider context is required")
	}
	if config.Path == "" {
		return nil, fmt.Errorf("mock provider path is required")
	}
	command := exec.CommandContext(ctx, config.Path, append([]string(nil), config.Args...)...) // #nosec G204 -- conformance executes the caller-selected external provider directly, never via a shell.
	command.Dir = config.Dir
	command.Env = append(os.Environ(), config.Env...)
	command.Stderr = config.Stderr
	if command.Stderr == nil {
		command.Stderr = io.Discard
	}
	stdinReader, stdin, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("mock provider stdin: %w", err)
	}
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		_ = stdinReader.Close()
		_ = stdin.Close()
		return nil, fmt.Errorf("mock provider stdout: %w", err)
	}
	command.Stdin = stdinReader
	command.Stdout = stdoutWriter
	if err := command.Start(); err != nil {
		_ = stdinReader.Close()
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stdoutWriter.Close()
		return nil, fmt.Errorf("start mock provider: %w", err)
	}
	_ = stdinReader.Close()
	_ = stdoutWriter.Close()
	process := &Provider{
		command: command,
		stdin:   stdin,
		stdout:  stdout,
		done:    make(chan struct{}),
	}
	go func() {
		waitErr := command.Wait()
		_ = stdin.Close()
		process.mu.Lock()
		process.err = waitErr
		process.mu.Unlock()
		close(process.done)
	}()
	return process, nil
}

// Read receives provider stdout. Provider protocol framing remains owned by the
// real provider SDK/client on either side of this byte stream.
func (p *Provider) Read(data []byte) (int, error) {
	if p == nil || p.stdout == nil {
		return 0, io.ErrClosedPipe
	}
	return p.stdout.Read(data)
}

// Write sends provider stdin.
func (p *Provider) Write(data []byte) (int, error) {
	if p == nil || p.stdin == nil {
		return 0, io.ErrClosedPipe
	}
	return p.stdin.Write(data)
}

// PID returns the external provider process ID.
func (p *Provider) PID() int {
	if p == nil || p.command == nil || p.command.Process == nil {
		return 0
	}
	return p.command.Process.Pid
}

// Exited closes after the external process has been reaped.
func (p *Provider) Exited() <-chan struct{} {
	if p == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return p.done
}

// Wait waits for the external process and returns its actual exit result.
func (p *Provider) Wait(ctx context.Context) error {
	if p == nil || ctx == nil {
		return fmt.Errorf("mock provider and context are required")
	}
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop closes provider stdin and waits for a graceful EOF shutdown. At the
// caller deadline it requests a kill and returns; the dedicated Wait goroutine
// continues reaping without extending that deadline.
func (p *Provider) Stop(ctx context.Context) error {
	if p == nil || ctx == nil {
		return fmt.Errorf("mock provider and context are required")
	}
	closeErr := p.stdin.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	waitErr := p.Wait(ctx)
	if errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded) {
		killErr := p.Crash()
		return errors.Join(closeErr, waitErr, killErr)
	}
	return errors.Join(closeErr, waitErr)
}

// Crash kills the external provider at the process boundary.
func (p *Provider) Crash() error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := p.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("crash mock provider: %w", err)
	}
	return nil
}

// Close forcefully releases stdio and reaps the external process. The expected
// non-zero status caused by cleanup is intentionally not returned.
func (p *Provider) Close() error {
	if p == nil {
		return nil
	}
	stdinErr := p.stdin.Close()
	if errors.Is(stdinErr, os.ErrClosed) {
		stdinErr = nil
	}
	killErr := p.Crash()
	stdoutErr := p.stdout.Close()
	if errors.Is(stdoutErr, os.ErrClosed) {
		stdoutErr = nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	waitErr := p.Wait(ctx)
	if !errors.Is(waitErr, context.Canceled) && !errors.Is(waitErr, context.DeadlineExceeded) {
		waitErr = nil
	}
	return errors.Join(stdinErr, killErr, stdoutErr, waitErr)
}
