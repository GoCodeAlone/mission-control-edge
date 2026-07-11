package provider

import (
	"fmt"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const (
	maxQueueEntries       = 4096
	maxOutboundQueueBytes = 256 << 20
	maxInFlightBytes      = 256 << 20
	maxInFlightRequests   = 1 << 16
	maxIdempotencyEntries = 1 << 20
	maxIdempotencyBytes   = 1 << 30
	maxSubscriptions      = 1 << 16
	maxHeartbeatInterval  = 5 * time.Minute
	maxShutdownTimeout    = 5 * time.Minute
)

// Limits bounds memory, concurrency, and shutdown behavior for both SDK ends.
// A zero-value Limits is intentionally invalid so callers cannot accidentally
// disable a bound.
type Limits struct {
	MaxEnvelopeBytes      uint64
	MaxOutboundQueue      int
	MaxInFlightRequests   int
	MaxIdempotencyEntries int
	MaxIdempotencyBytes   uint64
	MaxSubscriptions      int
	HeartbeatInterval     time.Duration
	ShutdownTimeout       time.Duration
}

// DefaultLimits returns conservative production limits for a provider process.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelopeBytes:      protocol.MaxMessageBytes,
		MaxOutboundQueue:      16,
		MaxInFlightRequests:   64,
		MaxIdempotencyEntries: 4_096,
		MaxIdempotencyBytes:   64 << 20,
		MaxSubscriptions:      256,
		HeartbeatInterval:     30 * time.Second,
		ShutdownTimeout:       5 * time.Second,
	}
}

// TestLimits returns smaller deterministic limits suitable for SDK contract
// tests. It is public so out-of-process provider fixtures can use the same
// limits as their test client.
func TestLimits() Limits {
	return Limits{
		MaxEnvelopeBytes:      64 << 10,
		MaxOutboundQueue:      16,
		MaxInFlightRequests:   16,
		MaxIdempotencyEntries: 64,
		MaxIdempotencyBytes:   4 << 20,
		MaxSubscriptions:      16,
		HeartbeatInterval:     100 * time.Millisecond,
		ShutdownTimeout:       time.Second,
	}
}

// Validate checks every limit, including upper bounds that prevent an
// untrusted configuration from turning a bounded SDK resource into an
// effectively unbounded one.
func (l Limits) Validate() error {
	if l.MaxEnvelopeBytes == 0 || l.MaxEnvelopeBytes > protocol.MaxMessageBytes {
		return fmt.Errorf("maximum envelope size is invalid")
	}
	if l.MaxOutboundQueue <= 0 || l.MaxOutboundQueue > maxQueueEntries {
		return fmt.Errorf("maximum outbound queue is invalid")
	}
	if uint64(l.MaxOutboundQueue) > uint64(maxOutboundQueueBytes)/l.MaxEnvelopeBytes {
		return fmt.Errorf("maximum outbound queue byte exposure is invalid")
	}
	if l.MaxInFlightRequests <= 0 || l.MaxInFlightRequests > maxInFlightRequests {
		return fmt.Errorf("maximum in-flight requests is invalid")
	}
	if uint64(l.MaxInFlightRequests) > uint64(maxInFlightBytes)/l.MaxEnvelopeBytes {
		return fmt.Errorf("maximum in-flight request byte exposure is invalid")
	}
	if l.MaxIdempotencyEntries <= 0 || l.MaxIdempotencyEntries > maxIdempotencyEntries {
		return fmt.Errorf("maximum idempotency entries is invalid")
	}
	if l.MaxIdempotencyBytes < l.MaxEnvelopeBytes || l.MaxIdempotencyBytes > maxIdempotencyBytes {
		return fmt.Errorf("maximum idempotency bytes is invalid")
	}
	if l.MaxSubscriptions <= 0 || l.MaxSubscriptions > maxSubscriptions {
		return fmt.Errorf("maximum subscriptions is invalid")
	}
	if l.HeartbeatInterval <= 0 || l.HeartbeatInterval > maxHeartbeatInterval {
		return fmt.Errorf("heartbeat interval is invalid")
	}
	if l.ShutdownTimeout <= 0 || l.ShutdownTimeout > maxShutdownTimeout {
		return fmt.Errorf("shutdown timeout is invalid")
	}
	return nil
}

type sdkOptions struct {
	limits Limits
}

// Option configures a provider SDK client or server.
type Option func(*sdkOptions) error

// WithLimits replaces the default SDK resource limits.
func WithLimits(limits Limits) Option {
	return func(options *sdkOptions) error {
		if err := limits.Validate(); err != nil {
			return fmt.Errorf("provider limits: %w", err)
		}
		options.limits = limits
		return nil
	}
}

func applyOptions(optionValues ...Option) (sdkOptions, error) {
	options := sdkOptions{limits: DefaultLimits()}
	for _, option := range optionValues {
		if option == nil {
			return sdkOptions{}, fmt.Errorf("provider option is nil")
		}
		if err := option(&options); err != nil {
			return sdkOptions{}, err
		}
	}
	if err := options.limits.Validate(); err != nil {
		return sdkOptions{}, fmt.Errorf("provider limits: %w", err)
	}
	return options, nil
}
