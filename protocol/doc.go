// Package protocol defines the provider-neutral Mission Control edge protocol.
//
//go:generate go run ../cmd/mc-schema --output ../schema
package protocol

const (
	// Version is the provider protocol namespace implemented by this package.
	Version = "mission-control.provider.v1alpha1"

	// MaxMessageBytes is the hard limit for one decoded protocol document.
	MaxMessageBytes = 4 << 20
)

// ProtocolVersion is the canonical wire value retained for descriptive APIs.
const ProtocolVersion = Version
