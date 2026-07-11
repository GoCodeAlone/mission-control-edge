// Package provider implements the Go SDK for Mission Control provider processes.
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

// QueryFunc handles one read-only provider capability.
type QueryFunc[Request, Result any] func(context.Context, Request) (Result, error)

// MutationFunc handles one mutating provider capability. MutationMeta retains
// the command envelope so provider implementations can reconcile retries and
// cancellation without interpreting gateway-owned canonical identifiers.
type MutationFunc[Request, Result any] func(context.Context, MutationMeta, Request) (Result, error)

type subscriptionContextKey struct{}

// SubscriptionContext returns the lifetime context for a subscription setup
// handler. The handler's direct context is canceled with the request; producers
// that outlive the acknowledgement must use this returned context.
func SubscriptionContext(setup context.Context) context.Context {
	if setup == nil {
		return context.Background()
	}
	if lifetime, ok := setup.Value(subscriptionContextKey{}).(context.Context); ok && lifetime != nil {
		return lifetime
	}
	return setup
}

// MutationMeta is the exact command metadata delivered to a mutation handler.
// RawCommand is retained only for integrity checks; SDK code must never log it.
type MutationMeta struct {
	protocol.Command
	CommandDigest protocol.Digest
	RawCommand    json.RawMessage
}

// Validate verifies that the decoded envelope and digest still bind the exact
// raw command received from the peer.
func (m MutationMeta) Validate() error {
	if err := m.Command.Validate(); err != nil {
		return fmt.Errorf("mutation command is invalid: %w", err)
	}
	if len(m.RawCommand) == 0 {
		return fmt.Errorf("raw mutation command is required")
	}
	digest, err := protocol.CommandDigest(m.RawCommand)
	if err != nil {
		return fmt.Errorf("raw mutation command is invalid: %w", err)
	}
	if m.CommandDigest != digest {
		return fmt.Errorf("mutation command digest does not match its raw envelope")
	}
	var decoded protocol.Command
	if err := protocol.Decode(m.RawCommand, &decoded); err != nil {
		return fmt.Errorf("raw mutation command is invalid: %w", err)
	}
	if !reflect.DeepEqual(decoded, m.Command) {
		return fmt.Errorf("mutation command does not match its raw envelope")
	}
	return nil
}

func newMutationMeta(command protocol.Command, rawCommand json.RawMessage) (MutationMeta, error) {
	digest, err := protocol.CommandDigest(rawCommand)
	if err != nil {
		return MutationMeta{}, err
	}
	meta := MutationMeta{
		Command:       command,
		CommandDigest: digest,
		RawCommand:    append(json.RawMessage(nil), rawCommand...),
	}
	if err := meta.Validate(); err != nil {
		return MutationMeta{}, err
	}
	return meta, nil
}

// ServerConfig describes provider-owned negotiation information. Transport and
// queue limits are supplied separately through Server options.
type ServerConfig struct {
	Manifest             protocol.ProviderManifest
	NativeRuntimeVersion string
	AuthenticationModes  []string
	ReplaySupported      bool
	ExperimentalFeatures []string
}

func (c ServerConfig) validate() error {
	if len(c.AuthenticationModes) == 0 {
		return fmt.Errorf("at least one authentication mode is required")
	}
	// ProviderInitializeResult owns the canonical validation rules for every
	// server-controlled negotiation field.
	candidate := protocol.ProviderInitializeResult{
		ProtocolVersion:      protocol.Version,
		Manifest:             c.Manifest,
		NativeRuntimeVersion: c.NativeRuntimeVersion,
		MaximumMessageBytes:  protocol.MaxMessageBytes,
		MaximumChunkBytes:    protocol.MaxTerminalChunkBytes,
		ReplaySupported:      c.ReplaySupported,
		AuthenticationMode:   c.AuthenticationModes[0],
		ExperimentalFeatures: append([]string(nil), c.ExperimentalFeatures...),
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("server configuration is invalid: %w", err)
	}
	seen := make(map[string]struct{}, len(c.AuthenticationModes))
	for _, mode := range c.AuthenticationModes {
		probe := candidate
		probe.AuthenticationMode = mode
		if err := probe.Validate(); err != nil {
			return fmt.Errorf("server authentication mode is invalid: %w", err)
		}
		if _, duplicate := seen[mode]; duplicate {
			return fmt.Errorf("server authentication mode is duplicated")
		}
		seen[mode] = struct{}{}
	}
	return nil
}

// TerminalDetachRequest is the SDK representation of the terminal.detach
// OpenRPC payload.
type TerminalDetachRequest struct {
	NativeSessionID protocol.NativeID `json:"native_session_id"`
	StreamID        string            `json:"stream_id"`
	SubscriptionID  string            `json:"subscription_id"`
}

// Validate checks a terminal detach payload against the same constraints used
// by terminal subscriptions and event subscription identifiers.
func (r TerminalDetachRequest) Validate() error {
	if err := validateCanonicalID(r.SubscriptionID); err != nil {
		return err
	}
	return (protocol.TerminalSubscribeRequest{
		NativeSessionID: r.NativeSessionID,
		StreamID:        r.StreamID,
		WindowBytes:     1,
	}).Validate()
}

// WorkspaceListRequest is the empty workspace.list OpenRPC request object.
type WorkspaceListRequest struct{}

// Validate accepts the closed empty workspace.list request object.
func (WorkspaceListRequest) Validate() error { return nil }

// PaneListResult is the SDK representation of the pane.list OpenRPC result.
type PaneListResult struct {
	Panes []protocol.Pane `json:"panes"`
}

// Validate checks list bounds, pane validity, and native pane uniqueness.
func (r PaneListResult) Validate() error {
	if len(r.Panes) > 4096 {
		return fmt.Errorf("too many panes")
	}
	seen := make(map[protocol.NativeID]struct{}, len(r.Panes))
	for _, pane := range r.Panes {
		if err := pane.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[pane.NativePaneID]; duplicate {
			return fmt.Errorf("pane is duplicated")
		}
		seen[pane.NativePaneID] = struct{}{}
	}
	return nil
}

// EventSubscription combines the wire result with replay and future events.
// The server emits replay before forwarding Events.
type EventSubscription struct {
	Result protocol.EventsSubscribeResult
	Replay []protocol.ProviderEvent
	Events <-chan protocol.ProviderEvent
}

// Validate checks the subscription acknowledgement and replay batch.
func (s EventSubscription) Validate() error {
	if err := s.Result.Validate(); err != nil {
		return err
	}
	for _, event := range s.Replay {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// TerminalSubscription combines the wire result with replay and future chunks.
// The server emits replay before forwarding Chunks.
type TerminalSubscription struct {
	Result protocol.EventsSubscribeResult
	Replay []protocol.TerminalChunk
	Chunks <-chan protocol.TerminalChunk
}

// Validate checks the subscription acknowledgement and replay batch.
func (s TerminalSubscription) Validate() error {
	if err := s.Result.Validate(); err != nil {
		return err
	}
	for _, chunk := range s.Replay {
		if err := chunk.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// TopologySubscription combines the wire result with replay and future
// topology snapshots.
type TopologySubscription struct {
	Result    protocol.EventsSubscribeResult
	Replay    []protocol.TopologySnapshot
	Snapshots <-chan protocol.TopologySnapshot
}

// Validate checks the subscription acknowledgement and replay batch.
func (s TopologySubscription) Validate() error {
	if err := s.Result.Validate(); err != nil {
		return err
	}
	for _, snapshot := range s.Replay {
		if err := snapshot.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Heartbeat is the payload carried by NotificationHeartbeat.
type Heartbeat struct {
	ObservedAt time.Time `json:"observed_at"`
}

// Validate requires the canonical UTC timestamp representation.
func (h Heartbeat) Validate() error {
	if h.ObservedAt.IsZero() || h.ObservedAt.Location() != time.UTC {
		return fmt.Errorf("heartbeat timestamp must be UTC")
	}
	return nil
}

// CancelRequest identifies an in-flight JSON-RPC request to cancel.
type CancelRequest struct {
	RequestID string `json:"request_id"`
}

// Validate bounds cancellation request identifiers without interpreting them.
func (r CancelRequest) Validate() error {
	return validateWireToken("cancellation request ID", r.RequestID)
}

func validateCanonicalID(value string) error {
	if len(value) == 0 || len(value) > 128 || !isASCIIAlphaNumeric(value[0]) {
		return fmt.Errorf("canonical ID is invalid")
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return fmt.Errorf("canonical ID is invalid")
		}
	}
	return nil
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// Notification is a validated SDK notification. Exactly one typed payload is
// present. For example, NotificationTerminalChunk selects TerminalChunk.
type Notification struct {
	Method         string
	Event          *protocol.ProviderEvent
	TerminalChunk  *protocol.TerminalChunk
	Topology       *protocol.TopologySnapshot
	Heartbeat      *Heartbeat
	Cancel         *CancelRequest
	TerminalCredit *protocol.TerminalCredit
}

// Validate ensures one typed and independently valid notification payload.
func (n Notification) Validate() error {
	if n.Method == "" {
		return fmt.Errorf("notification method is required")
	}
	values := []any{n.Event, n.TerminalChunk, n.Topology, n.Heartbeat, n.Cancel, n.TerminalCredit}
	present := 0
	for _, value := range values {
		if !isNil(value) {
			present++
		}
	}
	if present != 1 {
		return fmt.Errorf("notification requires exactly one payload")
	}
	for _, value := range values {
		if validatable, ok := value.(interface{ Validate() error }); ok && !isNil(value) {
			return validatable.Validate()
		}
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

func samePayload(left, right json.RawMessage) bool {
	var compactLeft, compactRight bytes.Buffer
	if json.Compact(&compactLeft, left) != nil || json.Compact(&compactRight, right) != nil {
		return false
	}
	return bytes.Equal(compactLeft.Bytes(), compactRight.Bytes())
}
