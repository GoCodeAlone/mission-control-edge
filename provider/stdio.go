package provider

import (
	"fmt"
	"io"
	"sync"
)

// StdioTransport joins a provider's input and output streams without assuming
// ownership of either stream. It deliberately has no logging surface: protocol
// envelopes, terminal output, and prompts must not be copied into diagnostics.
type StdioTransport struct {
	reader io.Reader
	writer io.Writer
	mu     sync.Mutex
}

// NewStdioTransport constructs a non-owning, concurrency-safe stdio transport.
func NewStdioTransport(reader io.Reader, writer io.Writer) (*StdioTransport, error) {
	if reader == nil {
		return nil, fmt.Errorf("stdio reader is required")
	}
	if writer == nil {
		return nil, fmt.Errorf("stdio writer is required")
	}
	return &StdioTransport{reader: reader, writer: writer}, nil
}

func (t *StdioTransport) Read(data []byte) (int, error) {
	if t == nil || t.reader == nil {
		return 0, fmt.Errorf("stdio reader is unavailable")
	}
	return t.reader.Read(data)
}

func (t *StdioTransport) Write(data []byte) (int, error) {
	if t == nil || t.writer == nil {
		return 0, fmt.Errorf("stdio writer is unavailable")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writer.Write(data)
}
