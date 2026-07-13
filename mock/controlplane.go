package mock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

// ControlPlaneRecord is the mock control-plane journal boundary. Its sequence
// is mock-owned and deliberately separate from provider stream sequence.
type ControlPlaneRecord struct {
	JournalSequence uint64                  `json:"journal_sequence"`
	Event           protocol.CanonicalEvent `json:"event"`
}

// Validate verifies a replay record using the public canonical event model.
func (r ControlPlaneRecord) Validate() error {
	if r.JournalSequence == 0 {
		return fmt.Errorf("mock journal sequence must be positive")
	}
	return r.Event.Validate()
}

// IngestResult reports public protocol sequence handling for one delivered
// copy. Exact duplicates have a zero JournalSequence because they are not
// committed twice.
type IngestResult struct {
	Outcome         protocol.SequenceOutcome
	JournalSequence uint64
	Event           protocol.CanonicalEvent
}

// ControlPlane is a deterministic in-memory sink at the canonical-event
// boundary. It delegates validation and stream ordering to protocol APIs.
type ControlPlane struct {
	faults  *Faults
	tracker *protocol.SequenceTracker

	ingestMu sync.Mutex
	replayMu sync.Mutex
	mu       sync.Mutex
	next     uint64
	records  []ControlPlaneRecord
}

// NewControlPlane creates an isolated canonical-event sink.
func NewControlPlane(faults *Faults) *ControlPlane {
	return &ControlPlane{faults: faults, tracker: protocol.NewSequenceTracker()}
}

// Ingest applies transport/control-plane faults before public protocol decode,
// canonical validation, and sequence tracking.
func (c *ControlPlane) Ingest(ctx context.Context, event protocol.CanonicalEvent) ([]IngestResult, error) {
	if c == nil || ctx == nil {
		return nil, fmt.Errorf("mock control plane and context are required")
	}
	c.ingestMu.Lock()
	defer c.ingestMu.Unlock()

	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	deliveries, err := c.faults.Apply(ctx, PointControlPlaneIngest, encoded)
	if err != nil {
		return nil, err
	}
	results := make([]IngestResult, 0, len(deliveries))
	for _, delivery := range deliveries {
		var delivered protocol.CanonicalEvent
		if err := protocol.Decode(delivery, &delivered); err != nil {
			return nil, err
		}
		providerEvent := delivered.ProviderEvent
		normalized, err := json.Marshal(providerEvent)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(normalized)
		outcome, err := c.tracker.Observe(protocol.EventCursor{
			ProviderID: providerEvent.ProviderID,
			Role:       providerEvent.Role,
			StreamID:   providerEvent.StreamID,
			EventID:    providerEvent.EventID,
			Sequence:   providerEvent.Sequence,
			Digest:     protocol.Digest("sha256:" + hex.EncodeToString(sum[:])),
		})
		if err != nil {
			return nil, err
		}
		result := IngestResult{Outcome: outcome, Event: cloneCanonicalEvent(delivered)}
		if outcome != protocol.SequenceDuplicate {
			c.mu.Lock()
			c.next++
			result.JournalSequence = c.next
			c.records = append(c.records, ControlPlaneRecord{
				JournalSequence: c.next,
				Event:           cloneCanonicalEvent(delivered),
			})
			c.mu.Unlock()
		}
		results = append(results, result)
	}
	return results, nil
}

// Records returns a detached snapshot of committed mock journal records.
func (c *ControlPlane) Records() []ControlPlaneRecord {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]ControlPlaneRecord, len(c.records))
	for index, record := range c.records {
		result[index] = ControlPlaneRecord{
			JournalSequence: record.JournalSequence,
			Event:           cloneCanonicalEvent(record.Event),
		}
	}
	return result
}

// Replay returns records after the given contiguous journal sequence, with
// scripted duplicate, reorder, gap, delay, oversize, and redaction faults.
func (c *ControlPlane) Replay(ctx context.Context, after uint64) ([]ControlPlaneRecord, error) {
	if c == nil || ctx == nil {
		return nil, fmt.Errorf("mock control plane and context are required")
	}
	c.replayMu.Lock()
	defer c.replayMu.Unlock()
	records := c.Records()
	result := make([]ControlPlaneRecord, 0, len(records))
	for _, record := range records {
		if record.JournalSequence <= after {
			continue
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		deliveries, err := c.faults.Apply(ctx, PointControlPlaneReplay, encoded)
		if err != nil {
			return nil, err
		}
		for _, delivery := range deliveries {
			decoded, err := decodeControlPlaneRecord(delivery)
			if err != nil {
				return nil, err
			}
			result = append(result, decoded)
		}
	}
	for _, delivery := range c.faults.Flush(PointControlPlaneReplay) {
		decoded, err := decodeControlPlaneRecord(delivery)
		if err != nil {
			return nil, err
		}
		result = append(result, decoded)
	}
	return result, nil
}

func decodeControlPlaneRecord(data []byte) (ControlPlaneRecord, error) {
	var record ControlPlaneRecord
	if err := protocol.Decode(data, &record); err != nil {
		return ControlPlaneRecord{}, err
	}
	return ControlPlaneRecord{
		JournalSequence: record.JournalSequence,
		Event:           cloneCanonicalEvent(record.Event),
	}, nil
}

func cloneCanonicalEvent(event protocol.CanonicalEvent) protocol.CanonicalEvent {
	clone := event
	clone.ProviderEvent.Payload = bytes.Clone(event.ProviderEvent.Payload)
	clone.ProviderEvent.Extensions = make(map[string]json.RawMessage, len(event.ProviderEvent.Extensions))
	for key, value := range event.ProviderEvent.Extensions {
		clone.ProviderEvent.Extensions[key] = bytes.Clone(value)
	}
	return clone
}
