package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"
)

const (
	MaxTerminalChunkBytes  = 256 << 10
	MaxTerminalWindowBytes = 8 << 20
)

type RuntimeSession struct {
	ProviderID      string                     `json:"provider_id"`
	NativeSessionID NativeID                   `json:"native_session_id"`
	Lifecycle       StateReport                `json:"lifecycle"`
	Health          StateReport                `json:"health"`
	Extensions      map[string]json.RawMessage `json:"extensions"`
}

func (s RuntimeSession) Validate() error {
	if err := validateID("provider_id", s.ProviderID); err != nil {
		return err
	}
	if err := s.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := s.Lifecycle.validate(AxisLifecycle); err != nil {
		return err
	}
	if err := s.Health.validate(AxisHealth); err != nil {
		return err
	}
	return validateExtensions(s.Extensions)
}

type RuntimeSessionRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
}

func (r RuntimeSessionRequest) Validate() error { return r.NativeSessionID.Validate() }

type RuntimeCheckpointRequest = RuntimeSessionRequest
type RuntimeAdoptRequest = RuntimeSessionRequest

type RuntimeRestoreRequest struct {
	SnapshotID          NativeID `json:"snapshot_id"`
	NativeEnvironmentID NativeID `json:"native_environment_id"`
}

func (r RuntimeRestoreRequest) Validate() error {
	if err := r.SnapshotID.Validate(); err != nil {
		return err
	}
	return r.NativeEnvironmentID.Validate()
}

type RuntimeListSessionsRequest struct{}

func (RuntimeListSessionsRequest) Validate() error { return nil }

type RuntimeListSessionsResult struct {
	Sessions []RuntimeSession `json:"sessions"`
}

func (r RuntimeListSessionsResult) Validate() error {
	if len(r.Sessions) > 4096 {
		return fmt.Errorf("too many runtime sessions")
	}
	seen := make(map[NativeID]struct{}, len(r.Sessions))
	for _, session := range r.Sessions {
		if err := session.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[session.NativeSessionID]; duplicate {
			return fmt.Errorf("runtime session is duplicated")
		}
		seen[session.NativeSessionID] = struct{}{}
	}
	return nil
}

type RuntimeCreateSessionRequest struct {
	NativeEnvironmentID NativeID        `json:"native_environment_id"`
	Name                string          `json:"name,omitempty"`
	Configuration       json.RawMessage `json:"configuration"`
	ConfigurationDigest Digest          `json:"configuration_digest"`
}

func (r RuntimeCreateSessionRequest) Validate() error {
	if err := r.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if r.Name != "" {
		if err := validateText("runtime session name", r.Name, 128); err != nil {
			return err
		}
	}
	return validateCompactJSONDigest("runtime configuration", r.Configuration, r.ConfigurationDigest)
}

type RuntimeTransferRequest struct {
	NativeSessionID     NativeID `json:"native_session_id"`
	NativeEnvironmentID NativeID `json:"native_environment_id"`
	CheckpointReference NativeID `json:"checkpoint_reference,omitempty"`
}

func (r RuntimeTransferRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := r.NativeEnvironmentID.Validate(); err != nil {
		return err
	}
	if r.CheckpointReference != "" {
		return r.CheckpointReference.Validate()
	}
	return nil
}

type RuntimeSessionResult struct {
	Session RuntimeSession `json:"session"`
}

func (r RuntimeSessionResult) Validate() error { return r.Session.Validate() }

type RuntimeSnapshot struct {
	NativeSessionID NativeID  `json:"native_session_id"`
	SnapshotID      NativeID  `json:"snapshot_id"`
	Digest          Digest    `json:"digest"`
	CreatedAt       time.Time `json:"created_at"`
}

type Workspace struct {
	ProviderID        string                     `json:"provider_id"`
	NativeWorkspaceID NativeID                   `json:"native_workspace_id"`
	Name              string                     `json:"name"`
	Extensions        map[string]json.RawMessage `json:"extensions"`
}

func (w Workspace) Validate() error {
	if err := validateID("provider_id", w.ProviderID); err != nil {
		return err
	}
	if err := w.NativeWorkspaceID.Validate(); err != nil {
		return err
	}
	if err := validateText("workspace name", w.Name, 256); err != nil {
		return err
	}
	return validateExtensions(w.Extensions)
}

type WorkspaceRequest struct {
	NativeWorkspaceID NativeID `json:"native_workspace_id"`
}

func (r WorkspaceRequest) Validate() error { return r.NativeWorkspaceID.Validate() }

type WorkspaceCreateRequest struct {
	Name          string          `json:"name"`
	Configuration json.RawMessage `json:"configuration"`
}

func (r WorkspaceCreateRequest) Validate() error {
	if err := validateText("workspace name", r.Name, 256); err != nil {
		return err
	}
	if len(r.Configuration) == 0 || !json.Valid(r.Configuration) {
		return fmt.Errorf("workspace configuration is invalid")
	}
	return nil
}

type WorkspaceListResult struct {
	Workspaces []Workspace `json:"workspaces"`
}

func (r WorkspaceListResult) Validate() error {
	if len(r.Workspaces) > 4096 {
		return fmt.Errorf("too many workspaces")
	}
	seen := make(map[NativeID]struct{}, len(r.Workspaces))
	for _, workspace := range r.Workspaces {
		if err := workspace.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[workspace.NativeWorkspaceID]; duplicate {
			return fmt.Errorf("workspace is duplicated")
		}
		seen[workspace.NativeWorkspaceID] = struct{}{}
	}
	return nil
}

type Pane struct {
	NativeWorkspaceID NativeID `json:"native_workspace_id"`
	NativePaneID      NativeID `json:"native_pane_id"`
	NativeSessionID   NativeID `json:"native_session_id,omitempty"`
	Rows              uint32   `json:"rows"`
	Columns           uint32   `json:"columns"`
}

func (p Pane) Validate() error {
	if err := p.NativeWorkspaceID.Validate(); err != nil {
		return err
	}
	if err := p.NativePaneID.Validate(); err != nil {
		return err
	}
	if p.NativeSessionID != "" {
		if err := p.NativeSessionID.Validate(); err != nil {
			return err
		}
	}
	if p.Rows == 0 || p.Columns == 0 || p.Rows > 10_000 || p.Columns > 10_000 {
		return fmt.Errorf("pane dimensions are invalid")
	}
	return nil
}

type TopologySnapshot struct {
	NativeWorkspaceID NativeID  `json:"native_workspace_id"`
	Revision          uint64    `json:"revision"`
	ObservedAt        time.Time `json:"observed_at"`
	Panes             []Pane    `json:"panes"`
}

func (s TopologySnapshot) Validate() error {
	if err := s.NativeWorkspaceID.Validate(); err != nil {
		return err
	}
	if s.Revision == 0 {
		return fmt.Errorf("topology revision must be positive")
	}
	if err := validateTime("observed_at", s.ObservedAt); err != nil {
		return err
	}
	if len(s.Panes) > 4096 {
		return fmt.Errorf("too many panes")
	}
	seen := make(map[NativeID]struct{}, len(s.Panes))
	for _, pane := range s.Panes {
		if err := pane.Validate(); err != nil {
			return err
		}
		if pane.NativeWorkspaceID != s.NativeWorkspaceID {
			return fmt.Errorf("pane belongs to another workspace")
		}
		if _, duplicate := seen[pane.NativePaneID]; duplicate {
			return fmt.Errorf("pane is duplicated")
		}
		seen[pane.NativePaneID] = struct{}{}
	}
	return nil
}

type PaneRequest struct {
	NativeWorkspaceID NativeID `json:"native_workspace_id"`
	NativePaneID      NativeID `json:"native_pane_id"`
}

func (r PaneRequest) Validate() error {
	if err := r.NativeWorkspaceID.Validate(); err != nil {
		return err
	}
	return r.NativePaneID.Validate()
}

type PaneCreateRequest struct {
	NativeWorkspaceID NativeID `json:"native_workspace_id"`
	NativeSessionID   NativeID `json:"native_session_id,omitempty"`
	Rows              uint32   `json:"rows"`
	Columns           uint32   `json:"columns"`
}

func (r PaneCreateRequest) Validate() error {
	if err := r.NativeWorkspaceID.Validate(); err != nil {
		return err
	}
	if r.NativeSessionID != "" {
		if err := r.NativeSessionID.Validate(); err != nil {
			return err
		}
	}
	if r.Rows == 0 || r.Columns == 0 || r.Rows > 10_000 || r.Columns > 10_000 {
		return fmt.Errorf("pane dimensions are invalid")
	}
	return nil
}

type PaneSplitDirection string

const (
	PaneSplitHorizontal PaneSplitDirection = "horizontal"
	PaneSplitVertical   PaneSplitDirection = "vertical"
)

type PaneSplitRequest struct {
	PaneRequest
	Direction PaneSplitDirection `json:"direction"`
}

func (r PaneSplitRequest) Validate() error {
	if err := r.PaneRequest.Validate(); err != nil {
		return err
	}
	if r.Direction != PaneSplitHorizontal && r.Direction != PaneSplitVertical {
		return fmt.Errorf("pane split direction is unsupported")
	}
	return nil
}

type PaneResizeRequest struct {
	PaneRequest
	Rows    uint32 `json:"rows"`
	Columns uint32 `json:"columns"`
}

func (r PaneResizeRequest) Validate() error {
	if err := r.PaneRequest.Validate(); err != nil {
		return err
	}
	if r.Rows == 0 || r.Columns == 0 || r.Rows > 10_000 || r.Columns > 10_000 {
		return fmt.Errorf("pane dimensions are invalid")
	}
	return nil
}

func (s RuntimeSnapshot) Validate() error {
	if err := s.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := s.SnapshotID.Validate(); err != nil {
		return err
	}
	if err := s.Digest.Validate(); err != nil {
		return err
	}
	return validateTime("created_at", s.CreatedAt)
}

type TerminalEncoding string

const (
	TerminalEncodingUTF8   TerminalEncoding = "utf-8"
	TerminalEncodingBase64 TerminalEncoding = "base64"
)

func (e TerminalEncoding) Validate() error {
	if e != TerminalEncodingUTF8 && e != TerminalEncodingBase64 {
		return fmt.Errorf("terminal encoding is unsupported")
	}
	return nil
}

type TerminalRedaction struct {
	Start  uint64 `json:"start"`
	End    uint64 `json:"end"`
	Reason string `json:"reason"`
}

func (r TerminalRedaction) validate(chunkStart, chunkEnd uint64) error {
	if r.Start < chunkStart || r.End <= r.Start || r.End > chunkEnd {
		return fmt.Errorf("terminal redaction range is invalid")
	}
	return validateToken("terminal redaction reason", r.Reason)
}

type TerminalChunk struct {
	NativeSessionID NativeID            `json:"native_session_id"`
	StreamID        string              `json:"stream_id"`
	Encoding        TerminalEncoding    `json:"encoding"`
	Sequence        uint64              `json:"sequence"`
	Offset          uint64              `json:"offset"`
	ObservedAt      time.Time           `json:"observed_at"`
	Data            string              `json:"data"`
	Replayed        bool                `json:"replayed"`
	Truncated       bool                `json:"truncated"`
	Redactions      []TerminalRedaction `json:"redactions"`
	CreditRemaining uint64              `json:"credit_remaining"`
}

func (c TerminalChunk) Validate() error {
	if err := c.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", c.StreamID); err != nil {
		return err
	}
	if err := c.Encoding.Validate(); err != nil {
		return err
	}
	if c.Sequence == 0 {
		return fmt.Errorf("terminal chunk sequence is invalid")
	}
	length, err := terminalDataLength(c.Encoding, c.Data)
	if err != nil || length == 0 || length > MaxTerminalChunkBytes {
		return fmt.Errorf("terminal chunk data is invalid")
	}
	if c.CreditRemaining > MaxTerminalWindowBytes {
		return fmt.Errorf("terminal window credit is invalid")
	}
	chunkEnd := c.Offset + length
	if chunkEnd < c.Offset {
		return fmt.Errorf("terminal chunk offset overflows")
	}
	if len(c.Redactions) > 1024 {
		return fmt.Errorf("too many terminal redactions")
	}
	previousEnd := c.Offset
	for _, redaction := range c.Redactions {
		if err := redaction.validate(c.Offset, chunkEnd); err != nil {
			return err
		}
		if redaction.Start < previousEnd {
			return fmt.Errorf("terminal redactions overlap or are out of order")
		}
		previousEnd = redaction.End
	}
	return validateTime("observed_at", c.ObservedAt)
}

func terminalDataLength(encoding TerminalEncoding, data string) (uint64, error) {
	switch encoding {
	case TerminalEncodingUTF8:
		if !utf8.ValidString(data) {
			return 0, fmt.Errorf("terminal text is not UTF-8")
		}
		return stringByteCount(data), nil
	case TerminalEncodingBase64:
		decoded, err := base64.StdEncoding.Strict().DecodeString(data)
		return byteCount(decoded), err
	default:
		return 0, fmt.Errorf("terminal encoding is unsupported")
	}
}

func byteCount(value []byte) uint64 {
	var size uint64
	for range value {
		size++
	}
	return size
}

func stringByteCount(value string) uint64 {
	var size uint64
	for index := 0; index < len(value); index++ {
		size++
	}
	return size
}

type TerminalReadRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	AfterOffset     uint64   `json:"after_offset"`
	MaximumBytes    uint64   `json:"maximum_bytes"`
}

func (r TerminalReadRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", r.StreamID); err != nil {
		return err
	}
	if r.MaximumBytes == 0 || r.MaximumBytes > MaxTerminalWindowBytes {
		return fmt.Errorf("terminal read limit is invalid")
	}
	return nil
}

type TerminalSubscribeRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	AfterOffset     uint64   `json:"after_offset"`
	WindowBytes     uint64   `json:"window_bytes"`
}

func (r TerminalSubscribeRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", r.StreamID); err != nil {
		return err
	}
	if r.WindowBytes == 0 || r.WindowBytes > MaxTerminalWindowBytes {
		return fmt.Errorf("terminal window is invalid")
	}
	return nil
}

type TerminalInputRequest struct {
	NativeSessionID NativeID         `json:"native_session_id"`
	StreamID        string           `json:"stream_id"`
	Encoding        TerminalEncoding `json:"encoding"`
	Data            string           `json:"data"`
}

func (r TerminalInputRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", r.StreamID); err != nil {
		return err
	}
	length, err := terminalDataLength(r.Encoding, r.Data)
	if err != nil || length == 0 || length > MaxTerminalChunkBytes {
		return fmt.Errorf("terminal input is invalid")
	}
	return nil
}

type TerminalKeysRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	Keys            []string `json:"keys"`
}

func (r TerminalKeysRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", r.StreamID); err != nil {
		return err
	}
	if len(r.Keys) == 0 || len(r.Keys) > 64 {
		return fmt.Errorf("terminal keys are invalid")
	}
	for _, key := range r.Keys {
		if err := validateText("terminal key", key, 64); err != nil {
			return err
		}
	}
	return nil
}

type TerminalResizeRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	Rows            uint32   `json:"rows"`
	Columns         uint32   `json:"columns"`
}

func (r TerminalResizeRequest) Validate() error {
	if err := r.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", r.StreamID); err != nil {
		return err
	}
	if r.Rows == 0 || r.Columns == 0 || r.Rows > 10_000 || r.Columns > 10_000 {
		return fmt.Errorf("terminal dimensions are invalid")
	}
	return nil
}

type TerminalAck struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	Sequence        uint64   `json:"sequence"`
	Offset          uint64   `json:"offset"`
}

func (a TerminalAck) Validate() error {
	if err := a.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", a.StreamID); err != nil {
		return err
	}
	if a.Sequence == 0 {
		return fmt.Errorf("terminal acknowledgement sequence is invalid")
	}
	return nil
}

type TerminalCredit struct {
	NativeSessionID NativeID `json:"native_session_id"`
	StreamID        string   `json:"stream_id"`
	Bytes           uint64   `json:"bytes"`
	ThroughOffset   uint64   `json:"through_offset"`
}

func (c TerminalCredit) Validate() error {
	if err := c.NativeSessionID.Validate(); err != nil {
		return err
	}
	if err := validateID("stream_id", c.StreamID); err != nil {
		return err
	}
	if c.Bytes == 0 || c.Bytes > MaxTerminalWindowBytes {
		return fmt.Errorf("terminal credit is invalid")
	}
	return nil
}
