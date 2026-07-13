// Package conformance runs the shared Mission Control provider contract against
// external provider processes.
package conformance

import (
	"fmt"
	"regexp"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const CaseSchemaVersion = "mission-control.conformance.cases.v1alpha1"

type CaseKind string

const (
	CaseInitializeRequired   CaseKind = "initialize_required"
	CaseOptionalCapabilities CaseKind = "optional_capabilities"
	CaseCapabilityMapping    CaseKind = "capability_mapping"
	CaseNotSupported         CaseKind = "not_supported"
	CaseEventDuplicate       CaseKind = "event_duplicate"
	CaseEventOutOfOrder      CaseKind = "event_out_of_order"
	CaseReplayGap            CaseKind = "replay_gap"
	CaseReconnect            CaseKind = "reconnect"
	CaseCancellation         CaseKind = "cancellation"
	CaseDeadline             CaseKind = "deadline"
	CaseBackpressure         CaseKind = "backpressure"
	CaseOversizedFrame       CaseKind = "oversized_frame"
	CaseCrashRecovery        CaseKind = "crash_recovery"
	CaseRedaction            CaseKind = "redaction"
	CaseDeliveryClass        CaseKind = "delivery_class"
)

var (
	caseIDPattern              = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,127}$`)
	extensionCapabilityPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,127}$`)
)

type Case struct {
	ID             string                  `json:"id"`
	Description    string                  `json:"description"`
	Kind           CaseKind                `json:"kind"`
	Required       bool                    `json:"required"`
	Capability     protocol.CapabilityName `json:"capability,omitempty"`
	DeliveryClass  protocol.DeliveryClass  `json:"delivery_class,omitempty"`
	WhenAdvertised bool                    `json:"when_advertised,omitempty"`
	RequiresReplay bool                    `json:"requires_replay,omitempty"`
	ExpectedCode   protocol.ErrorCode      `json:"expected_code,omitempty"`
}

func (c Case) Validate() error {
	if !caseIDPattern.MatchString(c.ID) {
		return fmt.Errorf("conformance case ID is invalid")
	}
	if len(c.Description) == 0 || len(c.Description) > 512 {
		return fmt.Errorf("conformance case description is invalid")
	}
	switch c.Kind {
	case CaseInitializeRequired, CaseOptionalCapabilities, CaseCapabilityMapping, CaseNotSupported,
		CaseEventDuplicate, CaseEventOutOfOrder, CaseReplayGap, CaseReconnect, CaseCancellation,
		CaseDeadline, CaseBackpressure, CaseOversizedFrame, CaseCrashRecovery, CaseRedaction,
		CaseDeliveryClass:
	default:
		return fmt.Errorf("conformance case kind is invalid")
	}
	if c.Capability != "" {
		if _, known := protocol.Capability(c.Capability); !known && !extensionCapabilityPattern.MatchString(string(c.Capability)) {
			return fmt.Errorf("conformance case capability is invalid")
		}
	}
	if c.DeliveryClass != "" {
		if c.Kind != CaseDeliveryClass {
			return fmt.Errorf("delivery class selector is valid only for delivery cases")
		}
		switch c.DeliveryClass {
		case protocol.DeliveryProviderIdempotent, protocol.DeliveryStateReconciled, protocol.DeliveryAtMostOnce:
		default:
			return fmt.Errorf("conformance delivery class is invalid")
		}
	} else if c.Kind == CaseDeliveryClass {
		return fmt.Errorf("delivery class case requires a delivery selector")
	}
	if c.WhenAdvertised && c.Capability == "" && c.DeliveryClass == "" {
		return fmt.Errorf("advertised-only case requires a capability or delivery selector")
	}
	if c.RequiresReplay && c.Kind != CaseReplayGap {
		return fmt.Errorf("replay requirement is valid only for replay cases")
	}
	if c.ExpectedCode != "" {
		if err := c.ExpectedCode.Validate(); err != nil {
			return fmt.Errorf("conformance expected error code is invalid")
		}
	}
	return nil
}

func (c Case) appliesTo(manifest protocol.ProviderManifest) bool {
	if c.Capability != "" && c.WhenAdvertised && !manifest.Supports(c.Capability) {
		return false
	}
	if c.DeliveryClass != "" && c.WhenAdvertised {
		_, supported := deliveryTargetCapability(manifest, c.DeliveryClass)
		return supported
	}
	return true
}

func deliveryTargetCapability(manifest protocol.ProviderManifest, class protocol.DeliveryClass) (protocol.CapabilityName, bool) {
	preferred := map[protocol.DeliveryClass][]protocol.CapabilityName{
		protocol.DeliveryProviderIdempotent: {"runtime.stop_session"},
		protocol.DeliveryStateReconciled:    {"runtime.create_session"},
		protocol.DeliveryAtMostOnce:         {"runtime.terminate_session"},
	}
	for _, capability := range preferred[class] {
		if manifest.Supports(capability) {
			return capability, true
		}
	}
	return "", false
}
