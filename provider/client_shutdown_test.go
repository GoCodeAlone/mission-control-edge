package provider

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

func TestClientPreservesResponseBeforeWriteAcknowledgementAndEOF(t *testing.T) {
	for _, test := range []struct {
		name   string
		result json.RawMessage
		code   protocol.ErrorCode
	}{
		{name: "completed response", result: json.RawMessage(`{"accepted":true}`)},
		{name: "invalid result still rejected", result: json.RawMessage(`{"accepted":true,"unknown":true}`), code: protocol.CodeInvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := TestLimits()
			client := &Client{
				limits:      limits,
				maximum:     limits.MaxEnvelopeBytes,
				initialized: true,
				pending:     make(map[string]chan clientOutcome),
				writes:      make(chan clientWrite),
				done:        make(chan struct{}),
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			peerDone := make(chan error, 1)
			go func() {
				select {
				case write := <-client.writes:
					request, err := decodeRPCRequest(write.frame, limits.MaxEnvelopeBytes)
					if err != nil {
						client.fail(err)
						peerDone <- err
						return
					}
					client.mu.Lock()
					outcome := client.pending[request.ID]
					delete(client.pending, request.ID)
					client.mu.Unlock()
					outcome <- clientOutcome{response: rpcResponse{JSONRPC: jsonRPCVersion, ID: request.ID, Result: test.result}}
					// The peer's final reply and EOF can arrive before the writer
					// goroutine publishes its acknowledgement.
					client.fail(io.EOF)
					peerDone <- nil
				case <-ctx.Done():
					peerDone <- ctx.Err()
				}
			}()
			var result struct {
				Accepted bool `json:"accepted"`
			}
			err := client.callValidated(ctx, "provider.shutdown", struct{}{}, &result, false, nil)
			if peerErr := <-peerDone; peerErr != nil {
				t.Fatalf("peer: %v", peerErr)
			}
			if test.code == "" {
				if err != nil || !result.Accepted {
					t.Fatalf("completed reply lost: accepted=%v error=%v", result.Accepted, err)
				}
			} else if !protocol.IsCode(err, test.code) {
				t.Fatalf("invalid reply error=%v, want %s", err, test.code)
			}
		})
	}
}
