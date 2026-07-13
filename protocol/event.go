package protocol

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var providerCoreEventTypes = map[string]struct{}{
	"session.discovered":         {},
	"session.created":            {},
	"session.state_changed":      {},
	"session.context_delivered":  {},
	"session.output_available":   {},
	"session.input_requested":    {},
	"session.approval_requested": {},
	"session.checkpoint_created": {},
	"session.completed":          {},
	"session.failed":             {},
	"session.disconnected":       {},
	"session.recovered":          {},
	"artifact.created":           {},
	"artifact.updated":           {},
	"artifact.deleted":           {},
	"artifact.review_requested":  {},
	"usage.updated":              {},
	"adapter.degraded":           {},
	"adapter.recovered":          {},
}

func validateProviderEventType(value string) error {
	if _, supported := providerCoreEventTypes[value]; supported {
		return nil
	}
	if extensionPattern.MatchString(value) {
		return nil
	}
	return fmt.Errorf("provider event type is unsupported")
}

// KnownProviderEventTypes returns the core event names providers may emit.
// Provider extensions use the reverse-DNS event namespace instead.
func KnownProviderEventTypes() []string {
	result := make([]string, 0, len(providerCoreEventTypes))
	for eventType := range providerCoreEventTypes {
		result = append(result, eventType)
	}
	sort.Strings(result)
	return result
}

type ProviderEvent struct {
	ProtocolVersion string                     `json:"protocol_version"`
	EventID         string                     `json:"event_id"`
	ProviderID      string                     `json:"provider_id"`
	Role            ProviderRole               `json:"role"`
	StreamID        string                     `json:"stream_id"`
	NativeSessionID NativeID                   `json:"native_session_id,omitempty"`
	Type            string                     `json:"type"`
	Sequence        uint64                     `json:"sequence"`
	ObservedAt      time.Time                  `json:"observed_at"`
	Payload         json.RawMessage            `json:"payload"`
	Extensions      map[string]json.RawMessage `json:"extensions"`
}

func (e ProviderEvent) Validate() error {
	if err := validateProtocol(e.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("event_id", e.EventID); err != nil {
		return err
	}
	if err := validateID("provider_id", e.ProviderID); err != nil {
		return err
	}
	if err := e.Role.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", e.StreamID); err != nil {
		return err
	}
	if e.NativeSessionID != "" {
		if err := e.NativeSessionID.Validate(); err != nil {
			return err
		}
	}
	if err := validateProviderEventType(e.Type); err != nil {
		return err
	}
	if strings.HasPrefix(e.Type, "session.") {
		if e.NativeSessionID == "" {
			return fmt.Errorf("session event requires a native session ID")
		}
		if e.Role == RoleProvider {
			return fmt.Errorf("session event requires a provider concern role")
		}
	}
	if e.Sequence == 0 {
		return fmt.Errorf("event sequence must be positive")
	}
	if err := validateTime("observed_at", e.ObservedAt); err != nil {
		return err
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return fmt.Errorf("event payload is invalid")
	}
	if err := rejectDuplicateKeys(e.Payload); err != nil {
		return fmt.Errorf("event payload is ambiguous")
	}
	allowedPayloadKeys := map[string]struct{}(nil)
	if e.Type == "session.state_changed" {
		var state StateReport
		if err := decodeJSON(e.Payload, &state, true); err != nil {
			return fmt.Errorf("session state payload is invalid")
		}
		if err := state.Validate(); err != nil {
			return fmt.Errorf("session state payload is invalid")
		}
		// StateReport.authority describes semantic-state provenance, not
		// gateway-owned canonical envelope authority.
		allowedPayloadKeys = map[string]struct{}{"authority": {}}
	}
	if strings.HasPrefix(e.Type, "artifact.") {
		var report ProviderArtifactReport
		if err := decodeJSON(e.Payload, &report, true); err != nil || report.Validate() != nil {
			return fmt.Errorf("artifact event payload is invalid")
		}
		if report.ProviderID != e.ProviderID || report.Role != e.Role || report.StreamID != e.StreamID || report.NativeSessionID != e.NativeSessionID {
			return fmt.Errorf("artifact event identity does not match its provider envelope")
		}
	}
	if err := rejectReservedProviderContent(e.Payload, allowedPayloadKeys); err != nil {
		return err
	}
	if err := rejectReservedExtensions(e.Extensions); err != nil {
		return err
	}
	return validateExtensions(e.Extensions)
}

type CanonicalEvent struct {
	ProtocolVersion string        `json:"protocol_version"`
	TenantID        string        `json:"tenant_id"`
	GatewayID       string        `json:"gateway_id"`
	SessionID       string        `json:"session_id,omitempty"`
	CorrelationID   string        `json:"correlation_id"`
	CausationID     string        `json:"causation_id,omitempty"`
	Sensitivity     Sensitivity   `json:"sensitivity"`
	Authority       string        `json:"authority"`
	ProviderEvent   ProviderEvent `json:"provider_event"`
}

func (e CanonicalEvent) Validate() error {
	if err := validateProtocol(e.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{"tenant_id": e.TenantID, "gateway_id": e.GatewayID, "correlation_id": e.CorrelationID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	requiresSession := strings.HasPrefix(e.ProviderEvent.Type, "session.") || e.ProviderEvent.NativeSessionID != ""
	if requiresSession && e.SessionID == "" {
		return fmt.Errorf("canonical session ID is required for a session-scoped provider event")
	}
	if e.SessionID != "" {
		if err := validateID("session_id", e.SessionID); err != nil {
			return err
		}
	}
	if e.CausationID != "" {
		if err := validateID("causation_id", e.CausationID); err != nil {
			return err
		}
	}
	if err := e.Sensitivity.Validate(); err != nil {
		return err
	}
	if e.Authority != "gateway-assigned" {
		return fmt.Errorf("canonical event authority must be gateway-assigned")
	}
	return e.ProviderEvent.Validate()
}

type EventCursor struct {
	ProviderID string
	Role       ProviderRole
	StreamID   string
	EventID    string
	Sequence   uint64
	Digest     Digest
}

type SequenceOutcome string

const (
	SequenceAccepted  SequenceOutcome = "accepted"
	SequenceDuplicate SequenceOutcome = "duplicate"
	SequenceGap       SequenceOutcome = "gap"
)

type eventStreamKey struct {
	providerID string
	role       ProviderRole
	streamID   string
}

type eventIDKey struct {
	stream  eventStreamKey
	eventID string
}

type sequenceStream struct {
	highest uint64
	seen    map[uint64]EventCursor
}

type SequenceTracker struct {
	mu       sync.Mutex
	streams  map[eventStreamKey]*sequenceStream
	eventIDs map[eventIDKey]EventCursor
}

func NewSequenceTracker() *SequenceTracker {
	return &SequenceTracker{
		streams:  map[eventStreamKey]*sequenceStream{},
		eventIDs: map[eventIDKey]EventCursor{},
	}
}

func (t *SequenceTracker) Observe(cursor EventCursor) (SequenceOutcome, error) {
	if t == nil {
		return "", protocolError(CodeInvalidArgument, "sequence tracker is required")
	}
	if err := validateID("provider_id", cursor.ProviderID); err != nil {
		return "", protocolError(CodeInvalidArgument, "event cursor provider is invalid")
	}
	if err := cursor.Role.Validate(); err != nil {
		return "", protocolError(CodeInvalidArgument, "event cursor role is invalid")
	}
	if err := validateID("stream_id", cursor.StreamID); err != nil {
		return "", protocolError(CodeInvalidArgument, "event cursor stream is invalid")
	}
	if err := validateID("event_id", cursor.EventID); err != nil || cursor.Sequence == 0 || cursor.Digest.Validate() != nil {
		return "", protocolError(CodeInvalidArgument, "event cursor is invalid")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	streamKey := eventStreamKey{providerID: cursor.ProviderID, role: cursor.Role, streamID: cursor.StreamID}
	idKey := eventIDKey{stream: streamKey, eventID: cursor.EventID}
	if prior, exists := t.eventIDs[idKey]; exists {
		if prior == cursor {
			return SequenceDuplicate, nil
		}
		return "", protocolError(CodeSequenceConflict, "event ID is already bound to different content")
	}

	stream := t.streams[streamKey]
	if stream == nil {
		stream = &sequenceStream{seen: map[uint64]EventCursor{}}
		t.streams[streamKey] = stream
	}
	if prior, exists := stream.seen[cursor.Sequence]; exists {
		if prior.EventID == cursor.EventID && prior.Digest == cursor.Digest {
			return SequenceDuplicate, nil
		}
		return "", protocolError(CodeSequenceConflict, "event sequence is already bound to different content")
	}
	outcome := SequenceAccepted
	if stream.highest != 0 && cursor.Sequence > stream.highest+1 {
		outcome = SequenceGap
	}
	stream.seen[cursor.Sequence] = cursor
	t.eventIDs[idKey] = cursor
	if cursor.Sequence > stream.highest {
		stream.highest = cursor.Sequence
	}
	return outcome, nil
}

type EventSubscriptionCursor struct {
	Role          ProviderRole `json:"role"`
	StreamID      string       `json:"stream_id"`
	AfterSequence uint64       `json:"after_sequence"`
}

func (c EventSubscriptionCursor) Validate() error {
	if err := c.Role.Validate(); err != nil {
		return err
	}
	return validateID("stream_id", c.StreamID)
}

type EventsSubscribeRequest struct {
	Cursors    []EventSubscriptionCursor `json:"cursors"`
	EventTypes []string                  `json:"event_types"`
	WindowSize uint32                    `json:"window_size"`
}

func (r EventsSubscribeRequest) Validate() error {
	if len(r.Cursors) > 4096 || len(r.EventTypes) > 256 {
		return fmt.Errorf("event subscription scope is too large")
	}
	seenCursors := make(map[eventStreamKey]struct{}, len(r.Cursors))
	for _, cursor := range r.Cursors {
		if err := cursor.Validate(); err != nil {
			return err
		}
		key := eventStreamKey{role: cursor.Role, streamID: cursor.StreamID}
		if _, duplicate := seenCursors[key]; duplicate {
			return fmt.Errorf("event subscription cursor is duplicated")
		}
		seenCursors[key] = struct{}{}
	}
	seenTypes := make(map[string]struct{}, len(r.EventTypes))
	for _, eventType := range r.EventTypes {
		if err := validateProviderEventType(eventType); err != nil {
			return err
		}
		if _, duplicate := seenTypes[eventType]; duplicate {
			return fmt.Errorf("event type is duplicated")
		}
		seenTypes[eventType] = struct{}{}
	}
	if r.WindowSize == 0 || r.WindowSize > 4096 {
		return fmt.Errorf("event subscription window is invalid")
	}
	return nil
}

type EventsSubscribeResult struct {
	SubscriptionID NativeID                  `json:"subscription_id"`
	Cursors        []EventSubscriptionCursor `json:"cursors"`
}

func (r EventsSubscribeResult) Validate() error {
	if err := r.SubscriptionID.Validate(); err != nil {
		return err
	}
	if len(r.Cursors) > 4096 {
		return fmt.Errorf("too many event subscription cursors")
	}
	for _, cursor := range r.Cursors {
		if err := cursor.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type EventsUnsubscribeRequest struct {
	SubscriptionID NativeID `json:"subscription_id"`
}

func (r EventsUnsubscribeRequest) Validate() error { return r.SubscriptionID.Validate() }
