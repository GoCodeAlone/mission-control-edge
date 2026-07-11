package provider

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

type responseAction struct {
	prepare  func()
	commit   func()
	rollback func()
	ctx      context.Context
	cancel   context.CancelFunc
}

type subscriptionAdmission struct {
	connection *serverConnection
	setup      context.Context
	lifetime   context.Context
	cancel     context.CancelFunc

	mu             sync.Mutex
	subscriptionID protocol.NativeID
	cleanupOnce    sync.Once
	terminal       *terminalFlow
	terminalKey    string
}

type terminalFlow struct {
	mu            sync.Mutex
	nativeSession protocol.NativeID
	streamID      string
	window        uint64
	remaining     uint64
	throughOffset uint64
	sequence      uint64
	replayAllowed bool
	wake          chan struct{}
}

func (c *serverConnection) beginSubscription(setup context.Context) (*subscriptionAdmission, error) {
	if !c.reserveSubscription() {
		return nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	lifetime, cancel := context.WithCancel(c.ctx) // #nosec G118 -- cleanup retains and invokes cancel for every admission path.
	return &subscriptionAdmission{
		connection: c,
		setup:      context.WithValue(setup, subscriptionContextKey{}, lifetime),
		lifetime:   lifetime,
		cancel:     cancel,
	}, nil
}

func (c *serverConnection) beginTerminalSubscription(setup context.Context, request protocol.TerminalSubscribeRequest) (*subscriptionAdmission, error) {
	if err := request.Validate(); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	lifetime, cancel := context.WithCancel(c.ctx) // #nosec G118 -- cleanup retains and invokes cancel for every admission path.
	key := string(request.NativeSessionID) + "\x00" + request.StreamID
	admission := &subscriptionAdmission{
		connection:  c,
		setup:       context.WithValue(setup, subscriptionContextKey{}, lifetime),
		lifetime:    lifetime,
		cancel:      cancel,
		terminalKey: key,
		terminal: &terminalFlow{
			nativeSession: request.NativeSessionID,
			streamID:      request.StreamID,
			window:        request.WindowBytes,
			remaining:     request.WindowBytes,
			throughOffset: request.AfterOffset,
			replayAllowed: c.canReplay(),
			wake:          make(chan struct{}),
		},
	}
	c.mu.Lock()
	if c.closing || c.subscriptions >= c.server.limits.MaxSubscriptions {
		c.mu.Unlock()
		cancel()
		return nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	if c.terminalStreams[key] != nil {
		c.mu.Unlock()
		cancel()
		return nil, newProtocolError(protocol.CodeConflict)
	}
	c.subscriptions++
	c.terminalStreams[key] = admission
	c.mu.Unlock()
	return admission, nil
}

func (a *subscriptionAdmission) cleanup() {
	if a == nil {
		return
	}
	a.cleanupOnce.Do(func() {
		a.cancel()
		a.mu.Lock()
		subscriptionID := a.subscriptionID
		a.mu.Unlock()
		a.connection.mu.Lock()
		if a.terminalKey != "" && a.connection.terminalStreams[a.terminalKey] == a {
			delete(a.connection.terminalStreams, a.terminalKey)
		}
		if subscriptionID != "" && a.connection.subscriptionCancels[subscriptionID] == a {
			delete(a.connection.subscriptionCancels, subscriptionID)
		}
		a.connection.mu.Unlock()
		a.connection.releaseSubscription()
	})
}

func (a *subscriptionAdmission) prepare(value any) (*responseAction, error) {
	if a == nil {
		return nil, nil
	}
	var subscriptionID protocol.NativeID
	var start func(context.Context, func())
	switch typed := value.(type) {
	case EventSubscription:
		if len(typed.Replay) > 0 && !a.connection.canReplay() {
			a.cleanup()
			return nil, newProtocolError(protocol.CodeInvalidArgument)
		}
		subscriptionID = typed.Result.SubscriptionID
		start = func(ctx context.Context, cleanup func()) { a.connection.startEventSubscription(ctx, typed, cleanup) }
	case TerminalSubscription:
		if a.terminal == nil {
			a.cleanup()
			return nil, newProtocolError(protocol.CodeInvalidArgument)
		}
		if len(typed.Replay) > 0 && !a.connection.canReplay() {
			a.cleanup()
			return nil, newProtocolError(protocol.CodeInvalidArgument)
		}
		for _, chunk := range typed.Replay {
			if err := validateTerminalChunkLimit(chunk, a.connection.currentMaximumChunk()); err != nil {
				a.cleanup()
				return nil, err
			}
		}
		subscriptionID = typed.Result.SubscriptionID
		start = func(ctx context.Context, cleanup func()) {
			a.connection.startTerminalSubscription(ctx, typed, a.terminal, cleanup)
		}
	case TopologySubscription:
		if len(typed.Replay) > 0 && !a.connection.canReplay() {
			a.cleanup()
			return nil, newProtocolError(protocol.CodeInvalidArgument)
		}
		subscriptionID = typed.Result.SubscriptionID
		start = func(ctx context.Context, cleanup func()) { a.connection.startTopologySubscription(ctx, typed, cleanup) }
	default:
		a.cleanup()
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if subscriptionID.Validate() != nil {
		a.cleanup()
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	a.connection.mu.Lock()
	if _, duplicate := a.connection.subscriptionCancels[subscriptionID]; duplicate {
		a.connection.mu.Unlock()
		a.cleanup()
		return nil, newProtocolError(protocol.CodeConflict)
	}
	a.mu.Lock()
	a.subscriptionID = subscriptionID
	a.mu.Unlock()
	a.connection.subscriptionCancels[subscriptionID] = a
	a.connection.mu.Unlock()
	return &responseAction{
		commit:   func() { start(a.lifetime, a.cleanup) },
		rollback: a.cleanup,
	}, nil
}

func (c *serverConnection) startEventSubscription(ctx context.Context, subscription EventSubscription, cleanup func()) {
	go func() {
		defer cleanup()
		for _, event := range subscription.Replay {
			if err := c.publish(NotificationEvent, event); err != nil {
				c.cancel()
				return
			}
		}
		if subscription.Events == nil {
			return
		}
		for {
			select {
			case event, ok := <-subscription.Events:
				if !ok {
					return
				}
				if err := event.Validate(); err != nil || c.publish(NotificationEvent, event) != nil {
					c.cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *serverConnection) startTerminalSubscription(ctx context.Context, subscription TerminalSubscription, flow *terminalFlow, cleanup func()) {
	go func() {
		defer cleanup()
		for _, chunk := range subscription.Replay {
			if err := flow.consume(ctx, chunk, c.currentMaximumChunk()); err != nil || c.publish(NotificationTerminalChunk, chunk) != nil {
				c.cancel()
				return
			}
		}
		if subscription.Chunks == nil {
			return
		}
		for {
			select {
			case chunk, ok := <-subscription.Chunks:
				if !ok {
					return
				}
				if err := flow.consume(ctx, chunk, c.currentMaximumChunk()); err != nil || c.publish(NotificationTerminalChunk, chunk) != nil {
					c.cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *serverConnection) startTopologySubscription(ctx context.Context, subscription TopologySubscription, cleanup func()) {
	go func() {
		defer cleanup()
		for _, snapshot := range subscription.Replay {
			if err := c.publish(NotificationTopologySnapshot, snapshot); err != nil {
				c.cancel()
				return
			}
		}
		if subscription.Snapshots == nil {
			return
		}
		for {
			select {
			case snapshot, ok := <-subscription.Snapshots:
				if !ok {
					return
				}
				if err := snapshot.Validate(); err != nil || c.publish(NotificationTopologySnapshot, snapshot) != nil {
					c.cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (c *serverConnection) publish(method string, value any) error {
	frame, err := marshalNotification(method, value, c.currentMaximum())
	if err != nil {
		return err
	}
	return c.enqueueDataWait(outboundFrame{data: frame})
}

func (c *serverConnection) enqueueDataWait(frame outboundFrame) error {
	select {
	case c.data <- frame:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

func (c *serverConnection) reserveSubscription() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.subscriptions >= c.server.limits.MaxSubscriptions || c.closing {
		return false
	}
	c.subscriptions++
	return true
}

func (c *serverConnection) releaseSubscription() {
	c.mu.Lock()
	if c.subscriptions > 0 {
		c.subscriptions--
	}
	c.mu.Unlock()
}

func (c *serverConnection) cancelSubscription(subscriptionID protocol.NativeID) {
	c.mu.Lock()
	admission := c.subscriptionCancels[subscriptionID]
	c.mu.Unlock()
	if admission != nil {
		admission.cancel()
	}
}

func (c *serverConnection) applyTerminalCredit(credit protocol.TerminalCredit) error {
	c.mu.Lock()
	admissions := make([]*subscriptionAdmission, 0, len(c.subscriptionCancels))
	for _, admission := range c.subscriptionCancels {
		if admission.terminal != nil && admission.terminal.nativeSession == credit.NativeSessionID && admission.terminal.streamID == credit.StreamID {
			admissions = append(admissions, admission)
		}
	}
	c.mu.Unlock()
	if len(admissions) != 1 {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return admissions[0].terminal.addCredit(credit)
}

func (f *terminalFlow) consume(ctx context.Context, chunk protocol.TerminalChunk, maximum uint64) error {
	if f == nil || chunk.NativeSessionID != f.nativeSession || chunk.StreamID != f.streamID {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateTerminalChunkLimit(chunk, maximum); err != nil {
		return err
	}
	if chunk.Replayed && !f.replayAllowed {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	size, err := terminalChunkSize(chunk)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	for {
		f.mu.Lock()
		if chunk.Offset != f.throughOffset {
			if !chunk.Truncated || chunk.Offset < f.throughOffset {
				f.mu.Unlock()
				return newProtocolError(protocol.CodeSequenceConflict)
			}
			f.throughOffset = chunk.Offset
		}
		if f.sequence != 0 && chunk.Sequence != f.sequence+1 && !chunk.Truncated {
			f.mu.Unlock()
			return newProtocolError(protocol.CodeSequenceConflict)
		}
		if size <= f.remaining {
			f.remaining -= size
			f.throughOffset += size
			f.sequence = chunk.Sequence
			remaining := f.remaining
			f.mu.Unlock()
			if chunk.CreditRemaining != remaining {
				return newProtocolError(protocol.CodeInvalidArgument)
			}
			return nil
		}
		wake := f.wake
		f.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return newProtocolError(errorCode(ctx.Err()))
		}
	}
}

func (f *terminalFlow) addCredit(credit protocol.TerminalCredit) error {
	if f == nil || credit.Validate() != nil || credit.NativeSessionID != f.nativeSession || credit.StreamID != f.streamID {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if credit.ThroughOffset != f.throughOffset || credit.Bytes > f.window-f.remaining {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	f.remaining += credit.Bytes
	close(f.wake)
	f.wake = make(chan struct{})
	return nil
}

// compile-time documentation of the terminal credit type consumed by the
// transport notification path.
var _ interface{ Validate() error } = protocol.TerminalCredit{}

func validateTerminalChunkLimit(chunk protocol.TerminalChunk, maximum uint64) error {
	if err := chunk.Validate(); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	size, err := terminalChunkSize(chunk)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if size > maximum {
		return newProtocolError(protocol.CodeMessageTooLarge)
	}
	return nil
}

func validateTerminalReadChunk(request protocol.TerminalReadRequest, chunk protocol.TerminalChunk, maximum uint64, replayAllowed bool) error {
	if err := request.Validate(); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateTerminalChunkLimit(chunk, maximum); err != nil {
		return err
	}
	if chunk.NativeSessionID != request.NativeSessionID || chunk.StreamID != request.StreamID {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	size, err := terminalChunkSize(chunk)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if size > request.MaximumBytes {
		return newProtocolError(protocol.CodeMessageTooLarge)
	}
	if chunk.Offset != request.AfterOffset && (!chunk.Truncated || chunk.Offset < request.AfterOffset) {
		return newProtocolError(protocol.CodeSequenceConflict)
	}
	if chunk.Replayed && !replayAllowed {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return nil
}

func terminalChunkSize(chunk protocol.TerminalChunk) (uint64, error) {
	return terminalDataSize(chunk.Encoding, chunk.Data)
}

func terminalDataSize(encoding protocol.TerminalEncoding, data string) (uint64, error) {
	switch encoding {
	case protocol.TerminalEncodingUTF8:
		return uint64(len([]byte(data))), nil
	case protocol.TerminalEncodingBase64:
		decoded, err := base64.StdEncoding.Strict().DecodeString(data)
		return uint64(len(decoded)), err
	default:
		return 0, fmt.Errorf("terminal encoding is unsupported")
	}
}
