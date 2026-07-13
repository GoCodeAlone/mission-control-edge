package protocol

import (
	"encoding/json"
	"fmt"
	"math"
	"time"
)

type State string
type StateAxis string
type StateAuthority string

const (
	AxisLifecycle StateAxis = "lifecycle"
	AxisActivity  StateAxis = "activity"
	AxisHealth    StateAxis = "health"

	AuthorityAuthoritative StateAuthority = "authoritative"
	AuthorityInferred      StateAuthority = "inferred"

	LifecycleProvisioning State = "provisioning"
	LifecycleStarting     State = "starting"
	LifecycleRunning      State = "running"
	LifecycleStopped      State = "stopped"
	LifecycleTerminated   State = "terminated"
	LifecycleArchived     State = "archived"
	LifecycleDisconnected State = "disconnected"
	LifecycleUnknown      State = "unknown"

	ActivityIdle               State = "idle"
	ActivityWorking            State = "working"
	ActivityWaitingForUser     State = "waiting_for_user"
	ActivityWaitingForApproval State = "waiting_for_approval"
	ActivityBlocked            State = "blocked"
	ActivityDone               State = "done"
	ActivityFailed             State = "failed"
	ActivityUnknown            State = "unknown"

	HealthHealthy     State = "healthy"
	HealthDegraded    State = "degraded"
	HealthUnreachable State = "unreachable"
	HealthUnknown     State = "unknown"
)

type StateReport struct {
	Axis       StateAxis      `json:"axis"`
	State      State          `json:"state"`
	Source     string         `json:"source"`
	ObservedAt time.Time      `json:"observed_at"`
	Sequence   uint64         `json:"sequence"`
	Confidence float64        `json:"confidence"`
	ExpiresAt  *time.Time     `json:"expires_at,omitempty"`
	Authority  StateAuthority `json:"authority"`
	Status     string         `json:"status,omitempty"`
}

func (r StateReport) validate(expected StateAxis) error {
	if r.Axis != expected {
		return fmt.Errorf("state axis does not match field")
	}
	if !validState(expected, r.State) {
		return fmt.Errorf("state value is unsupported for axis")
	}
	if err := validateText("state source", r.Source, 128); err != nil {
		return err
	}
	if err := validateTime("observed_at", r.ObservedAt); err != nil {
		return err
	}
	if r.Sequence == 0 {
		return fmt.Errorf("state sequence must be positive")
	}
	if math.IsNaN(r.Confidence) || math.IsInf(r.Confidence, 0) || r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("state confidence must be between zero and one")
	}
	if r.ExpiresAt != nil {
		if err := validateTime("expires_at", *r.ExpiresAt); err != nil {
			return err
		}
		if !r.ExpiresAt.After(r.ObservedAt) {
			return fmt.Errorf("state expiry must follow observation")
		}
	}
	if r.Authority != AuthorityAuthoritative && r.Authority != AuthorityInferred {
		return fmt.Errorf("state authority is unsupported")
	}
	if r.Status != "" {
		if err := validateText("state status", r.Status, 1024); err != nil {
			return err
		}
	}
	return nil
}

func (r StateReport) Validate() error {
	switch r.Axis {
	case AxisLifecycle, AxisActivity, AxisHealth:
		return r.validate(r.Axis)
	default:
		return fmt.Errorf("state axis is unsupported")
	}
}

func validState(axis StateAxis, state State) bool {
	allowed := map[StateAxis]map[State]struct{}{
		AxisLifecycle: {LifecycleProvisioning: {}, LifecycleStarting: {}, LifecycleRunning: {}, LifecycleStopped: {}, LifecycleTerminated: {}, LifecycleArchived: {}, LifecycleDisconnected: {}, LifecycleUnknown: {}},
		AxisActivity:  {ActivityIdle: {}, ActivityWorking: {}, ActivityWaitingForUser: {}, ActivityWaitingForApproval: {}, ActivityBlocked: {}, ActivityDone: {}, ActivityFailed: {}, ActivityUnknown: {}},
		AxisHealth:    {HealthHealthy: {}, HealthDegraded: {}, HealthUnreachable: {}, HealthUnknown: {}},
	}
	_, ok := allowed[axis][state]
	return ok
}

type Session struct {
	ProtocolVersion string                     `json:"protocol_version"`
	SessionID       string                     `json:"session_id"`
	GatewayID       string                     `json:"gateway_id"`
	Environment     ProviderBinding            `json:"environment"`
	Runtime         *ProviderBinding           `json:"runtime,omitempty"`
	Harness         ProviderBinding            `json:"harness"`
	Lifecycle       StateReport                `json:"lifecycle"`
	Activity        StateReport                `json:"activity"`
	Health          StateReport                `json:"health"`
	ContextVersion  string                     `json:"context_version"`
	Extensions      map[string]json.RawMessage `json:"extensions"`
}

func (s Session) Validate() error {
	if err := validateProtocol(s.ProtocolVersion); err != nil {
		return err
	}
	if err := validateID("session_id", s.SessionID); err != nil {
		return err
	}
	if err := validateID("gateway_id", s.GatewayID); err != nil {
		return err
	}
	if err := s.Environment.Validate(); err != nil {
		return err
	}
	if s.Runtime != nil {
		if err := s.Runtime.Validate(); err != nil {
			return err
		}
	}
	if err := s.Harness.Validate(); err != nil {
		return err
	}
	if err := s.Lifecycle.validate(AxisLifecycle); err != nil {
		return err
	}
	if err := s.Activity.validate(AxisActivity); err != nil {
		return err
	}
	if err := s.Health.validate(AxisHealth); err != nil {
		return err
	}
	if err := validateID("context_version", s.ContextVersion); err != nil {
		return err
	}
	return validateExtensions(s.Extensions)
}
