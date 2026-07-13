// Package mock provides deterministic boundary faults for the public provider
// conformance harness. It never interprets or implements provider RPC methods.
package mock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

// FaultPoint identifies an external byte boundary where a fault may occur.
type FaultPoint string

const (
	PointGatewayToProvider  FaultPoint = "gateway.provider"
	PointProviderToGateway  FaultPoint = "provider.gateway"
	PointControlPlaneIngest FaultPoint = "control-plane.ingest"
	PointControlPlaneReplay FaultPoint = "control-plane.replay"
)

// FaultAction is one deterministic transformation or failure.
type FaultAction string

const (
	ActionDisconnect   FaultAction = "disconnect"
	ActionCrash        FaultAction = "crash"
	ActionDelay        FaultAction = "delay"
	ActionDuplicate    FaultAction = "duplicate"
	ActionOutOfOrder   FaultAction = "out_of_order"
	ActionReplayGap    FaultAction = "replay_gap"
	ActionBackpressure FaultAction = "backpressure"
	ActionOversize     FaultAction = "oversize"
	ActionRedact       FaultAction = "redact"
)

var (
	ErrDisconnected = errors.New("mock boundary disconnected")
	ErrCrash        = errors.New("mock provider crash")
)

// Fault runs once at the numbered occurrence of Point. Multiple faults at the
// same point and occurrence compose in declaration order.
type Fault struct {
	Point       FaultPoint
	Occurrence  uint64
	Action      FaultAction
	Contains    []byte
	Delay       time.Duration
	Copies      int
	Size        int
	Match       []byte
	Replacement []byte
	Gate        <-chan struct{}
}

// Faults is a concurrency-safe, occurrence-scripted fault plan.
type Faults struct {
	mu      sync.Mutex
	steps   []faultStep
	pending map[FaultPoint][][]byte
}

type faultStep struct {
	fault Fault
	seen  uint64
	used  bool
}

// NewFaults validates and copies a deterministic fault script.
func NewFaults(values ...Fault) (*Faults, error) {
	result := &Faults{
		steps:   make([]faultStep, 0, len(values)),
		pending: make(map[FaultPoint][][]byte),
	}
	for _, value := range values {
		if err := value.validate(); err != nil {
			return nil, err
		}
		value.Contains = bytes.Clone(value.Contains)
		value.Match = bytes.Clone(value.Match)
		value.Replacement = bytes.Clone(value.Replacement)
		result.steps = append(result.steps, faultStep{fault: value})
	}
	return result, nil
}

func (f Fault) validate() error {
	switch f.Point {
	case PointGatewayToProvider, PointProviderToGateway, PointControlPlaneIngest, PointControlPlaneReplay:
	default:
		return fmt.Errorf("mock fault point is invalid")
	}
	if f.Occurrence == 0 {
		return fmt.Errorf("mock fault occurrence must be positive")
	}
	switch f.Action {
	case ActionDisconnect, ActionCrash, ActionOutOfOrder, ActionReplayGap:
	case ActionDelay:
		if f.Delay <= 0 {
			return fmt.Errorf("mock delay must be positive")
		}
	case ActionDuplicate:
		if f.Copies < 2 || f.Copies > 16 {
			return fmt.Errorf("mock duplicate copies must be between 2 and 16")
		}
	case ActionBackpressure:
		if f.Gate == nil {
			return fmt.Errorf("mock backpressure gate is required")
		}
	case ActionOversize:
		if f.Size <= 0 || f.Size > protocol.MaxMessageBytes+1 {
			return fmt.Errorf("mock oversize target is invalid")
		}
	case ActionRedact:
		if len(f.Match) == 0 {
			return fmt.Errorf("mock redaction match is required")
		}
	default:
		return fmt.Errorf("mock fault action is invalid")
	}
	return nil
}

// Apply transforms one complete frame or record. Returned slices never alias
// payload or the configured fault values.
func (f *Faults) Apply(ctx context.Context, point FaultPoint, payload []byte) ([][]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("mock fault context is required")
	}
	if f == nil {
		return [][]byte{bytes.Clone(payload)}, nil
	}

	f.mu.Lock()
	steps := make([]Fault, 0)
	for index := range f.steps {
		step := &f.steps[index]
		if step.used || step.fault.Point != point || len(step.fault.Contains) > 0 && !bytes.Contains(payload, step.fault.Contains) {
			continue
		}
		step.seen++
		if step.seen == step.fault.Occurrence {
			step.used = true
			steps = append(steps, step.fault)
		}
	}
	pending := cloneFrames(f.pending[point])
	delete(f.pending, point)
	f.mu.Unlock()

	frames := [][]byte{bytes.Clone(payload)}
	if len(pending) > 0 {
		frames = append(frames, pending...)
	}
	for _, step := range steps {
		switch step.Action {
		case ActionDelay:
			timer := time.NewTimer(step.Delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return nil, ctx.Err()
			}
		case ActionBackpressure:
			select {
			case <-step.Gate:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case ActionDuplicate:
			duplicated := make([][]byte, 0, len(frames)*step.Copies)
			for _, frame := range frames {
				for range step.Copies {
					duplicated = append(duplicated, bytes.Clone(frame))
				}
			}
			frames = duplicated
		case ActionOutOfOrder:
			f.mu.Lock()
			f.pending[point] = append(f.pending[point], cloneFrames(frames)...)
			f.mu.Unlock()
			frames = nil
		case ActionReplayGap:
			frames = nil
		case ActionOversize:
			for index, frame := range frames {
				if len(frame) >= step.Size {
					continue
				}
				oversized := bytes.Repeat([]byte{' '}, step.Size)
				copy(oversized, frame)
				frames[index] = oversized
			}
		case ActionRedact:
			for index, frame := range frames {
				frames[index] = bytes.ReplaceAll(frame, step.Match, step.Replacement)
			}
		case ActionDisconnect:
			return nil, ErrDisconnected
		case ActionCrash:
			return nil, ErrCrash
		}
	}
	return cloneFrames(frames), nil
}

// Flush releases a frame held by an out-of-order fault when a boundary closes.
func (f *Faults) Flush(point FaultPoint) [][]byte {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	result := cloneFrames(f.pending[point])
	delete(f.pending, point)
	return result
}

// Remaining reports scripted actions that have not reached their occurrence.
func (f *Faults) Remaining() int {
	if f == nil {
		return 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	remaining := 0
	for _, step := range f.steps {
		if !step.used {
			remaining++
		}
	}
	return remaining
}

func cloneFrames(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index, value := range values {
		result[index] = bytes.Clone(value)
	}
	return result
}
