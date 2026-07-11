package provider

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sync"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

type clientOutcome struct {
	response rpcResponse
	err      error
}

type clientLocalResponseError struct{ err error }

func (e *clientLocalResponseError) Error() string { return e.err.Error() }
func (e *clientLocalResponseError) Unwrap() error { return e.err }

type clientWrite struct {
	ctx    context.Context
	frame  []byte
	result chan error
}

type clientResultValidator func(json.RawMessage) error

type clientCapabilityCodec struct {
	request clientResultValidator
	result  clientResultValidator
}

func newClientCapabilityCodec[Request, Result any]() clientCapabilityCodec {
	return clientCapabilityCodec{
		request: decodeCanonicalClientValue[Request],
		result:  decodeCanonicalClientValue[Result],
	}
}

func decodeCanonicalClientValue[Value any](raw json.RawMessage) error {
	var value Value
	return decodeRPCValue(raw, &value)
}

var clientCapabilityCodecs = map[protocol.CapabilityName]clientCapabilityCodec{
	"provider.initialize":   newClientCapabilityCodec[protocol.ProviderInitializeRequest, protocol.ProviderInitializeResult](),
	"provider.health":       newClientCapabilityCodec[protocol.ProviderHealthRequest, protocol.ProviderHealthResult](),
	"provider.capabilities": newClientCapabilityCodec[protocol.ProviderCapabilitiesRequest, protocol.ProviderCapabilitiesResult](),
	"provider.shutdown":     newClientCapabilityCodec[protocol.ProviderShutdownRequest, protocol.OperationResult](),
	"events.subscribe":      newClientCapabilityCodec[protocol.EventsSubscribeRequest, protocol.EventsSubscribeResult](),
	"events.unsubscribe":    newClientCapabilityCodec[protocol.EventsUnsubscribeRequest, protocol.OperationResult](),
	"command.get_result":    newClientCapabilityCodec[protocol.CommandGetResultRequest, protocol.CommandResult](),

	"environment.inspect":   newClientCapabilityCodec[protocol.EnvironmentInspectRequest, protocol.EnvironmentResult](),
	"environment.health":    newClientCapabilityCodec[protocol.EnvironmentHealthRequest, protocol.EnvironmentResult](),
	"environment.provision": newClientCapabilityCodec[protocol.EnvironmentProvisionRequest, protocol.EnvironmentResult](),
	"environment.mount":     newClientCapabilityCodec[protocol.EnvironmentMountRequest, protocol.EnvironmentResult](),
	"environment.shutdown":  newClientCapabilityCodec[protocol.EnvironmentShutdownRequest, protocol.EnvironmentResult](),

	"runtime.list_sessions":     newClientCapabilityCodec[protocol.RuntimeListSessionsRequest, protocol.RuntimeListSessionsResult](),
	"runtime.get_session":       newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.create_session":    newClientCapabilityCodec[protocol.RuntimeCreateSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.stop_session":      newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.terminate_session": newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.attach":            newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.detach":            newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.snapshot":          newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSnapshot](),
	"runtime.checkpoint":        newClientCapabilityCodec[protocol.RuntimeCheckpointRequest, protocol.RuntimeSnapshot](),
	"runtime.restore":           newClientCapabilityCodec[protocol.RuntimeRestoreRequest, protocol.RuntimeSessionResult](),
	"runtime.adopt":             newClientCapabilityCodec[protocol.RuntimeAdoptRequest, protocol.RuntimeSessionResult](),
	"runtime.resume":            newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.clone":             newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.fork":              newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),
	"runtime.migrate":           newClientCapabilityCodec[protocol.RuntimeTransferRequest, protocol.RuntimeSessionResult](),
	"runtime.export":            newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSnapshot](),
	"runtime.import":            newClientCapabilityCodec[protocol.RuntimeRestoreRequest, protocol.RuntimeSessionResult](),
	"runtime.archive":           newClientCapabilityCodec[protocol.RuntimeSessionRequest, protocol.RuntimeSessionResult](),

	"terminal.read":       newClientCapabilityCodec[protocol.TerminalReadRequest, protocol.TerminalChunk](),
	"terminal.subscribe":  newClientCapabilityCodec[protocol.TerminalSubscribeRequest, protocol.EventsSubscribeResult](),
	"terminal.send_input": newClientCapabilityCodec[protocol.TerminalInputRequest, protocol.TerminalAck](),
	"terminal.send_keys":  newClientCapabilityCodec[protocol.TerminalKeysRequest, protocol.TerminalAck](),
	"terminal.resize":     newClientCapabilityCodec[protocol.TerminalResizeRequest, protocol.TerminalAck](),
	"terminal.attach":     newClientCapabilityCodec[protocol.TerminalSubscribeRequest, protocol.EventsSubscribeResult](),
	"terminal.detach":     newClientCapabilityCodec[TerminalDetachRequest, protocol.TerminalAck](),

	"workspace.list":   newClientCapabilityCodec[WorkspaceListRequest, protocol.WorkspaceListResult](),
	"workspace.get":    newClientCapabilityCodec[protocol.WorkspaceRequest, protocol.Workspace](),
	"workspace.create": newClientCapabilityCodec[protocol.WorkspaceCreateRequest, protocol.Workspace](),
	"workspace.close":  newClientCapabilityCodec[protocol.WorkspaceRequest, protocol.OperationResult](),
	"topology.get":     newClientCapabilityCodec[protocol.WorkspaceRequest, protocol.TopologySnapshot](),
	"topology.subscribe": newClientCapabilityCodec[
		protocol.WorkspaceRequest, protocol.EventsSubscribeResult,
	](),
	"pane.list":   newClientCapabilityCodec[protocol.WorkspaceRequest, PaneListResult](),
	"pane.get":    newClientCapabilityCodec[protocol.PaneRequest, protocol.Pane](),
	"pane.create": newClientCapabilityCodec[protocol.PaneCreateRequest, protocol.Pane](),
	"pane.split":  newClientCapabilityCodec[protocol.PaneSplitRequest, protocol.Pane](),
	"pane.focus":  newClientCapabilityCodec[protocol.PaneRequest, protocol.Pane](),
	"pane.resize": newClientCapabilityCodec[protocol.PaneResizeRequest, protocol.Pane](),
	"pane.close":  newClientCapabilityCodec[protocol.PaneRequest, protocol.OperationResult](),

	"harness.list":    newClientCapabilityCodec[protocol.HarnessListRequest, protocol.HarnessListResult](),
	"harness.inspect": newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.HarnessSessionResult](),
	"harness.launch":  newClientCapabilityCodec[protocol.HarnessLaunchRequest, protocol.HarnessSessionResult](),
	"harness.resume":  newClientCapabilityCodec[protocol.HarnessResumeRequest, protocol.HarnessSessionResult](),
	"harness.stop":    newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.OperationResult](),

	"agent.send_message":          newClientCapabilityCodec[protocol.AgentMessageRequest, protocol.AgentStateResult](),
	"agent.interrupt":             newClientCapabilityCodec[protocol.AgentControlRequest, protocol.OperationResult](),
	"agent.cancel":                newClientCapabilityCodec[protocol.AgentControlRequest, protocol.OperationResult](),
	"agent.get_state":             newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.AgentStateResult](),
	"agent.get_usage":             newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.AgentUsageResult](),
	"agent.get_pending_approvals": newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.ApprovalListResult](),
	"agent.get_tools":             newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.AgentToolsResult](),
	"agent.get_native_identity":   newClientCapabilityCodec[protocol.HarnessSessionRequest, protocol.AgentNativeIdentityResult](),

	"context.deliver": newClientCapabilityCodec[protocol.ContextDeliverRequest, protocol.ContextDeliverResult](),
	"context.confirm": newClientCapabilityCodec[protocol.ContextConfirmRequest, protocol.ContextConfirmResult](),

	"approval.list":    newClientCapabilityCodec[protocol.ApprovalListRequest, protocol.ApprovalListResult](),
	"approval.approve": newClientCapabilityCodec[protocol.ApprovalActionRequest, protocol.ApprovalActionResult](),
	"approval.reject":  newClientCapabilityCodec[protocol.ApprovalActionRequest, protocol.ApprovalActionResult](),
	"approval.expire":  newClientCapabilityCodec[protocol.ApprovalActionRequest, protocol.ApprovalActionResult](),

	"artifact.list":     newClientCapabilityCodec[protocol.ArtifactListRequest, protocol.ArtifactListResult](),
	"artifact.register": newClientCapabilityCodec[protocol.ArtifactRegisterRequest, protocol.ArtifactRegisterResult](),
}

func clientCapabilityCodecFor(capability protocol.CapabilityName) (clientCapabilityCodec, bool) {
	codec, ok := clientCapabilityCodecs[capability]
	return codec, ok
}

type terminalStreamKey struct {
	nativeSession protocol.NativeID
	streamID      string
}

type clientTerminalFlow struct {
	mu             sync.Mutex
	nativeSession  protocol.NativeID
	streamID       string
	subscriptionID protocol.NativeID
	attachDigest   protocol.Digest
	attachPending  int
	established    bool
	unknown        bool
	retiring       bool
	closed         bool
	window         uint64
	remaining      uint64
	throughOffset  uint64
	sequence       uint64
}

// Client speaks the provider JSON-RPC protocol over a pair of streams. One
// goroutine owns reads and frameWriter serializes every write.
type Client struct {
	reader *bufio.Reader
	writer *frameWriter
	limits Limits

	mu            sync.Mutex
	pending       map[string]chan clientOutcome
	initialized   bool
	manifest      protocol.ProviderManifest
	maximum       uint64
	terminalMax   uint64
	replay        bool
	readErr       error
	closed        bool
	terminalFlows map[terminalStreamKey]*clientTerminalFlow

	notifications     chan Notification
	notificationInput chan Notification
	writes            chan clientWrite
	done              chan struct{}
	closeOnce         sync.Once
	transportOnce     sync.Once
	closers           []io.Closer
	transportErr      error
}

// NewClient starts a provider-protocol client. The client owns and closes
// reader/writer when they implement io.Closer.
func NewClient(reader io.Reader, writer io.Writer, optionValues ...Option) (*Client, error) {
	if reader == nil || writer == nil {
		return nil, fmt.Errorf("provider client streams are required")
	}
	options, err := applyOptions(optionValues...)
	if err != nil {
		return nil, err
	}
	client := &Client{
		reader:            bufio.NewReaderSize(reader, 64<<10),
		writer:            newFrameWriter(writer, options.limits.MaxEnvelopeBytes),
		limits:            options.limits,
		pending:           make(map[string]chan clientOutcome),
		maximum:           options.limits.MaxEnvelopeBytes,
		terminalMax:       protocol.MaxTerminalChunkBytes,
		terminalFlows:     make(map[terminalStreamKey]*clientTerminalFlow),
		notifications:     make(chan Notification, options.limits.MaxOutboundQueue),
		notificationInput: make(chan Notification, options.limits.MaxOutboundQueue),
		writes:            make(chan clientWrite, options.limits.MaxOutboundQueue),
		done:              make(chan struct{}),
	}
	if closer, ok := reader.(io.Closer); ok {
		client.closers = append(client.closers, closer)
	}
	if closer, ok := writer.(io.Closer); ok && !sameCloser(client.closers, closer) {
		client.closers = append(client.closers, closer)
	}
	go client.writeLoop()
	go client.notificationLoop()
	go client.readLoop()
	return client, nil
}

func sameCloser(existing []io.Closer, candidate io.Closer) bool {
	candidateValue := reflect.ValueOf(candidate)
	for _, closer := range existing {
		closerValue := reflect.ValueOf(closer)
		if candidateValue.IsValid() && closerValue.IsValid() && candidateValue.Type() == closerValue.Type() && candidateValue.Comparable() && closerValue.Interface() == candidateValue.Interface() {
			return true
		}
	}
	return false
}

// Initialize negotiates the protocol exactly once.
func (c *Client) Initialize(ctx context.Context, request protocol.ProviderInitializeRequest) (protocol.ProviderInitializeResult, error) {
	if err := request.Validate(); err != nil {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	c.mu.Lock()
	alreadyInitialized := c.initialized
	c.mu.Unlock()
	if alreadyInitialized {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeConflict)
	}
	var result protocol.ProviderInitializeResult
	codec, ok := clientCapabilityCodecFor("provider.initialize")
	if !ok {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := c.callValidated(ctx, "provider.initialize", request, &result, true, codec.result); err != nil {
		return protocol.ProviderInitializeResult{}, err
	}
	if err := protocol.ValidateProviderNegotiation(request, result); err != nil {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	c.mu.Lock()
	if c.initialized {
		c.mu.Unlock()
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeConflict)
	}
	c.initialized = true
	c.manifest = result.Manifest
	c.maximum = min(c.limits.MaxEnvelopeBytes, result.MaximumMessageBytes)
	c.terminalMax = min(uint64(protocol.MaxTerminalChunkBytes), result.MaximumChunkBytes)
	c.replay = result.ReplaySupported
	c.writer.mu.Lock()
	c.writer.maximumBytes = c.maximum
	c.writer.mu.Unlock()
	c.mu.Unlock()
	return result, nil
}

func (c *Client) Health(ctx context.Context) (protocol.ProviderHealthResult, error) {
	var result protocol.ProviderHealthResult
	err := c.Query(ctx, "provider.health", protocol.ProviderHealthRequest{}, &result)
	return result, err
}

func (c *Client) Capabilities(ctx context.Context) (protocol.ProviderCapabilitiesResult, error) {
	var result protocol.ProviderCapabilitiesResult
	err := c.Query(ctx, "provider.capabilities", protocol.ProviderCapabilitiesRequest{}, &result)
	return result, err
}

// Query invokes a read-only provider capability with a typed request/result.
func (c *Client) Query(ctx context.Context, capability protocol.CapabilityName, request, result any) error {
	if capability == "terminal.subscribe" {
		var subscription protocol.TerminalSubscribeRequest
		switch typed := request.(type) {
		case protocol.TerminalSubscribeRequest:
			subscription = typed
		case *protocol.TerminalSubscribeRequest:
			if typed == nil {
				return newProtocolError(protocol.CodeInvalidArgument)
			}
			subscription = *typed
		default:
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		destination, ok := result.(*protocol.EventsSubscribeResult)
		if !ok || destination == nil {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		value, err := c.SubscribeTerminal(ctx, subscription)
		if err != nil {
			return err
		}
		*destination = value
		return nil
	}
	return c.query(ctx, capability, request, result)
}

func (c *Client) query(ctx context.Context, capability protocol.CapabilityName, request, result any) error {
	if ctx == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return newProtocolError(errorCode(err))
	}
	if !c.isInitialized() {
		return newProtocolError(protocol.CodeConflict)
	}
	c.mu.Lock()
	manifest := c.manifest
	descriptor, advertised := manifest.Capability(capability)
	c.mu.Unlock()
	if !advertised {
		return notSupported(capability, manifestCapabilities(manifest))
	}
	if descriptor.Mutating {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	canonicalRequest, err := canonicalClientParameter(request)
	if err != nil {
		return err
	}
	if err := c.validateReplayRequest(capability, canonicalRequest); err != nil {
		return err
	}
	if isExtensionCapability(capability) {
		if err := validateClientExtensionRaw(canonicalRequest); err != nil {
			return err
		}
	} else {
		codec, ok := clientCapabilityCodecFor(capability)
		if !ok || codec.request == nil {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		if err := codec.request(canonicalRequest); err != nil {
			return normalizeProtocolError(err)
		}
	}
	if err := c.callValidated(ctx, string(capability), canonicalRequest, result, false, c.responseValidator(capability, canonicalRequest)); err != nil {
		if isSubscriptionCapability(capability) && (isClientLocalResponseError(err) || ambiguousTerminalFlowError(err)) {
			c.closeTransport()
			c.fail(err)
		}
		return err
	}
	if err := validateRuntimeWorkspaceExtensions(result); err != nil {
		return normalizeProtocolError(err)
	}
	if isExtensionCapability(capability) {
		return validateClientExtensionValue(result)
	}
	if capability == "terminal.read" {
		chunk, ok := result.(*protocol.TerminalChunk)
		if !ok {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		readRequest, ok := terminalReadRequestValue(canonicalRequest)
		if !ok {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		return validateTerminalReadChunk(readRequest, *chunk, c.currentTerminalMaximum(), c.canReplay())
	}
	return nil
}

// Mutate invokes the capability named by command and preserves all retry and
// cancellation identity supplied by the caller.
func (c *Client) Mutate(ctx context.Context, command protocol.Command, result any) error {
	if ctx == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return newProtocolError(errorCode(err))
	}
	c.mu.Lock()
	initialized := c.initialized
	manifest := c.manifest
	c.mu.Unlock()
	if !initialized {
		return newProtocolError(protocol.CodeConflict)
	}
	if err := command.ValidateAgainstManifest(manifest); err != nil {
		return normalizeProtocolError(err)
	}
	var attachFlow *clientTerminalFlow
	if command.Capability == "terminal.attach" {
		var request protocol.TerminalSubscribeRequest
		if err := decodeRPCValue(command.Payload, &request); err != nil {
			return err
		}
		if err := c.validateReplayRequest(command.Capability, request); err != nil {
			return err
		}
		if _, ok := result.(*protocol.EventsSubscribeResult); !ok {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
		var err error
		attachFlow, err = c.reserveAttachedTerminalFlow(request, command)
		if err != nil {
			return err
		}
	}
	finishAttach := func(subscriptionID protocol.NativeID, err error) error {
		if attachFlow == nil {
			return err
		}
		return c.completeAttachedTerminalFlow(attachFlow, subscriptionID, err)
	}
	if command.Capability == "terminal.send_input" {
		if err := c.validateTerminalInput(command.Payload); err != nil {
			return finishAttach("", err)
		}
	}
	if isExtensionCapability(command.Capability) {
		if err := validateClientExtensionValue(command.Payload); err != nil {
			return finishAttach("", err)
		}
	} else {
		codec, ok := clientCapabilityCodecFor(command.Capability)
		if !ok || codec.request == nil {
			return finishAttach("", newProtocolError(protocol.CodeInvalidArgument))
		}
		if err := codec.request(command.Payload); err != nil {
			return finishAttach("", normalizeProtocolError(err))
		}
	}
	if err := c.callValidated(ctx, string(command.Capability), command, result, false, c.responseValidator(command.Capability, command.Payload)); err != nil {
		if attachFlow != nil && isClientLocalResponseError(err) {
			c.closeTransport()
			c.fail(err)
		}
		return finishAttach("", err)
	}
	if err := validateRuntimeWorkspaceExtensions(result); err != nil {
		return finishAttach("", normalizeProtocolError(err))
	}
	if isExtensionCapability(command.Capability) {
		if err := validateClientExtensionValue(result); err != nil {
			return finishAttach("", err)
		}
	}
	if attachFlow != nil {
		if err := finishAttach(result.(*protocol.EventsSubscribeResult).SubscriptionID, nil); err != nil {
			return err
		}
	}
	if command.Capability == "terminal.detach" || command.Capability == "events.unsubscribe" {
		c.removeTerminalFlowForCommand(command)
	}
	return nil
}

func (c *Client) SubscribeTerminal(ctx context.Context, request protocol.TerminalSubscribeRequest) (protocol.EventsSubscribeResult, error) {
	if !c.isInitialized() {
		return protocol.EventsSubscribeResult{}, newProtocolError(protocol.CodeConflict)
	}
	if request.Validate() != nil {
		return protocol.EventsSubscribeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := c.validateReplayRequest("terminal.subscribe", request); err != nil {
		return protocol.EventsSubscribeResult{}, err
	}
	if ctx == nil {
		return protocol.EventsSubscribeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return protocol.EventsSubscribeResult{}, newProtocolError(errorCode(err))
	}
	flow, err := c.reserveTerminalFlow(request)
	if err != nil {
		return protocol.EventsSubscribeResult{}, err
	}
	var result protocol.EventsSubscribeResult
	if err := c.query(ctx, "terminal.subscribe", request, &result); err != nil {
		if isClientLocalResponseError(err) || ambiguousTerminalFlowError(err) {
			c.closeTransport()
			c.fail(err)
		}
		c.releaseTerminalFlow(flow)
		return protocol.EventsSubscribeResult{}, err
	}
	if err := flow.bindSubscription(result.SubscriptionID); err != nil {
		c.closeTransport()
		c.fail(err)
		c.releaseTerminalFlow(flow)
		return protocol.EventsSubscribeResult{}, err
	}
	return result, nil
}

// SendTerminalCredit replenishes a negotiated terminal stream window.
func (c *Client) SendTerminalCredit(ctx context.Context, credit protocol.TerminalCredit) error {
	if !c.isInitialized() || ctx == nil || credit.Validate() != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	flow := c.terminalFlow(credit.NativeSessionID, credit.StreamID)
	if flow == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return c.sendTerminalCredit(ctx, credit, flow)
}

func (c *Client) sendTerminalCredit(ctx context.Context, credit protocol.TerminalCredit, flow *clientTerminalFlow) error {
	if flow == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	frame, err := marshalNotification(NotificationTerminalCredit, credit, c.currentMaximum())
	if err != nil {
		return normalizeProtocolError(err)
	}
	flow.mu.Lock()
	defer flow.mu.Unlock()
	if flow.closed || !c.isTerminalFlowActive(flow) {
		return newProtocolError(protocol.CodeConflict)
	}
	if credit.ThroughOffset != flow.throughOffset || credit.Bytes > flow.window-flow.remaining {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := c.write(ctx, frame); err != nil {
		return normalizeProtocolError(err)
	}
	flow.remaining += credit.Bytes
	return nil
}

// Notifications exposes validated event, terminal, heartbeat, cancellation,
// and credit notifications. Closing the client closes the channel.
func (c *Client) Notifications() <-chan Notification { return c.notifications }

func (c *Client) isInitialized() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.initialized
}

func (c *Client) callValidated(ctx context.Context, method string, parameter, destination any, initialization bool, validate clientResultValidator) error {
	if ctx == nil || destination == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return newProtocolError(errorCode(err))
	}
	requestID, err := randomRequestID()
	if err != nil {
		return newProtocolError(protocol.CodeUnavailable)
	}
	maximum := c.currentMaximum()
	frame, err := marshalRequest(requestID, method, parameter, maximum)
	if err != nil {
		return normalizeProtocolError(err)
	}
	outcome := make(chan clientOutcome, 1)
	c.mu.Lock()
	if c.closed {
		err := c.readErr
		c.mu.Unlock()
		if err != nil {
			return normalizeProtocolError(err)
		}
		return newProtocolError(protocol.CodeUnavailable)
	}
	if !initialization && !c.initialized {
		c.mu.Unlock()
		return newProtocolError(protocol.CodeConflict)
	}
	if len(c.pending) >= c.limits.MaxInFlightRequests {
		c.mu.Unlock()
		return newProtocolError(protocol.CodeResourceExhausted)
	}
	c.pending[requestID] = outcome
	c.mu.Unlock()
	if err := c.write(ctx, frame); err != nil {
		c.removePending(requestID)
		return normalizeProtocolError(err)
	}

	select {
	case result := <-outcome:
		return finishClientOutcome(result, destination, validate)
	default:
	}
	select {
	case result := <-outcome:
		return finishClientOutcome(result, destination, validate)
	case <-ctx.Done():
		select {
		case result := <-outcome:
			return finishClientOutcome(result, destination, validate)
		default:
		}
		cancelFrame, marshalErr := marshalNotification(NotificationCancel, CancelRequest{RequestID: requestID}, maximum)
		if marshalErr == nil {
			c.enqueueNotification(cancelFrame)
		}
		c.removePending(requestID)
		return newProtocolError(errorCode(ctx.Err()))
	case <-c.done:
		select {
		case result := <-outcome:
			return finishClientOutcome(result, destination, validate)
		default:
		}
		c.removePending(requestID)
		return newProtocolError(protocol.CodeUnavailable)
	}
}

func finishClientOutcome(result clientOutcome, destination any, validate clientResultValidator) error {
	if result.err != nil {
		return normalizeProtocolError(result.err)
	}
	if result.response.Error == nil && validate != nil {
		if err := validate(result.response.Result); err != nil {
			return &clientLocalResponseError{err: normalizeProtocolError(err)}
		}
	}
	err := decodeStrictResult(result.response, destination)
	if err != nil && result.response.Error == nil {
		return &clientLocalResponseError{err: err}
	}
	return err
}

func (c *Client) write(ctx context.Context, frame []byte) error {
	result := make(chan error, 1)
	request := clientWrite{ctx: ctx, frame: append([]byte(nil), frame...), result: result}
	select {
	case c.writes <- request:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return newProtocolError(protocol.CodeUnavailable)
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		c.closeTransport()
		c.fail(ctx.Err())
		return ctx.Err()
	case <-c.done:
		return newProtocolError(protocol.CodeUnavailable)
	}
}

func (c *Client) enqueueNotification(frame []byte) {
	request := clientWrite{ctx: context.Background(), frame: append([]byte(nil), frame...), result: make(chan error, 1)}
	select {
	case c.writes <- request:
	default:
		c.closeTransport()
		c.fail(newProtocolError(protocol.CodeResourceExhausted))
	}
}

func (c *Client) writeLoop() {
	for {
		select {
		case request := <-c.writes:
			if err := request.ctx.Err(); err != nil {
				request.result <- err
				continue
			}
			err := c.writer.write(request.frame)
			request.result <- err
			if err != nil {
				c.closeTransport()
				c.fail(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func decodeStrictResult(response rpcResponse, destination any) error {
	if response.Error != nil {
		return response.Error.protocolError()
	}
	decoder := json.NewDecoder(bytes.NewReader(response.Result))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return decodeRPCResult(response, destination)
}

func (c *Client) readLoop() {
	for {
		frame, err := readFrame(c.reader, c.currentMaximum())
		if err != nil {
			c.fail(err)
			return
		}
		var fields map[string]json.RawMessage
		if err := protocol.Decode(frame, &fields); err != nil {
			c.fail(err)
			return
		}
		if _, notification := fields["method"]; notification {
			request, err := decodeRPCRequest(frame, c.currentMaximum())
			if err != nil || !request.isNotification() {
				c.fail(newProtocolError(protocol.CodeInvalidArgument))
				return
			}
			notificationValue, err := c.decodeNotification(request)
			if err != nil {
				c.fail(err)
				return
			}
			select {
			case c.notificationInput <- notificationValue:
			case <-c.done:
				return
			default:
				c.fail(newProtocolError(protocol.CodeResourceExhausted))
				return
			}
			continue
		}
		response, err := decodeRPCResponse(frame, c.currentMaximum())
		if err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		outcome := c.pending[response.ID]
		delete(c.pending, response.ID)
		c.mu.Unlock()
		if outcome == nil {
			continue
		}
		outcome <- clientOutcome{response: response}
	}
}

func (c *Client) notificationLoop() {
	defer close(c.notifications)
	for {
		select {
		case notification := <-c.notificationInput:
			select {
			case c.notifications <- notification:
			case <-c.done:
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) decodeNotification(request rpcRequest) (Notification, error) {
	notification := Notification{Method: request.Method}
	switch request.Method {
	case NotificationEvent:
		var value protocol.ProviderEvent
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.Event = &value
	case NotificationTerminalChunk:
		var value protocol.TerminalChunk
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.TerminalChunk = &value
		if err := c.consumeTerminalChunk(value); err != nil {
			return Notification{}, err
		}
	case NotificationTopologySnapshot:
		var value protocol.TopologySnapshot
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.Topology = &value
	case NotificationHeartbeat:
		var value Heartbeat
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.Heartbeat = &value
	case NotificationCancel:
		var value CancelRequest
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.Cancel = &value
	case NotificationTerminalCredit:
		var value protocol.TerminalCredit
		if err := decodeRPCParam(request, &value); err != nil {
			return Notification{}, err
		}
		notification.TerminalCredit = &value
	default:
		return Notification{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := notification.Validate(); err != nil {
		return Notification{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	return notification, nil
}

func (c *Client) validateReplayRequest(capability protocol.CapabilityName, request any) error {
	c.mu.Lock()
	replay := c.replay
	c.mu.Unlock()
	switch capability {
	case "terminal.read":
		var value protocol.TerminalReadRequest
		if err := decodeClientRequest(request, &value); err != nil {
			return err
		}
		if !replay && value.AfterOffset > 0 {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	case "terminal.subscribe", "terminal.attach":
		var value protocol.TerminalSubscribeRequest
		if err := decodeClientRequest(request, &value); err != nil {
			return err
		}
		if !replay && value.AfterOffset > 0 {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	case "events.subscribe":
		var value protocol.EventsSubscribeRequest
		if err := decodeClientRequest(request, &value); err != nil {
			return err
		}
		for _, cursor := range value.Cursors {
			if !replay && cursor.AfterSequence > 0 {
				return newProtocolError(protocol.CodeInvalidArgument)
			}
		}
	}
	return nil
}

func decodeClientRequest(request any, destination any) error {
	raw, err := json.Marshal(request)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return decodeRPCValue(raw, destination)
}

func canonicalClientParameter(value any) (json.RawMessage, error) {
	if err := validateOutbound(value); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	raw, err := json.Marshal(value)
	if err != nil || validateObject(raw) != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return append(json.RawMessage(nil), raw...), nil
}

func (c *Client) canReplay() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.replay
}

func (c *Client) validateTerminalInput(raw json.RawMessage) error {
	var request protocol.TerminalInputRequest
	if err := decodeRPCValue(raw, &request); err != nil || request.Validate() != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	size, err := terminalChunkSize(protocol.TerminalChunk{Encoding: request.Encoding, Data: request.Data})
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if size > c.currentTerminalMaximum() {
		return newProtocolError(protocol.CodeMessageTooLarge)
	}
	return nil
}

func isExtensionCapability(capability protocol.CapabilityName) bool {
	_, core := protocol.Capability(capability)
	return !core
}

func (c *Client) responseValidator(capability protocol.CapabilityName, request any) clientResultValidator {
	if isExtensionCapability(capability) {
		return validateClientExtensionRaw
	}
	codec, ok := clientCapabilityCodecFor(capability)
	if !ok || codec.result == nil {
		return func(json.RawMessage) error { return newProtocolError(protocol.CodeInvalidArgument) }
	}
	canonical := codec.result
	switch capability {
	case "terminal.read":
		readRequest, ok := terminalReadRequestValue(request)
		if !ok {
			return func(json.RawMessage) error { return newProtocolError(protocol.CodeInvalidArgument) }
		}
		maximum := c.currentTerminalMaximum()
		replay := c.canReplay()
		return func(raw json.RawMessage) error {
			if err := canonical(raw); err != nil {
				return err
			}
			var chunk protocol.TerminalChunk
			if err := decodeRPCValue(raw, &chunk); err != nil {
				return err
			}
			return validateTerminalReadChunk(readRequest, chunk, maximum, replay)
		}
	case "runtime.list_sessions":
		return func(raw json.RawMessage) error {
			if err := canonical(raw); err != nil {
				return err
			}
			var value protocol.RuntimeListSessionsResult
			if err := decodeRPCValue(raw, &value); err != nil {
				return err
			}
			return validateRuntimeWorkspaceExtensions(value)
		}
	case "runtime.get_session", "runtime.create_session", "runtime.stop_session", "runtime.terminate_session",
		"runtime.attach", "runtime.detach", "runtime.restore", "runtime.adopt", "runtime.resume", "runtime.clone",
		"runtime.fork", "runtime.migrate", "runtime.import", "runtime.archive":
		return func(raw json.RawMessage) error {
			if err := canonical(raw); err != nil {
				return err
			}
			var value protocol.RuntimeSessionResult
			if err := decodeRPCValue(raw, &value); err != nil {
				return err
			}
			return validateRuntimeWorkspaceExtensions(value)
		}
	case "workspace.list":
		return func(raw json.RawMessage) error {
			if err := canonical(raw); err != nil {
				return err
			}
			var value protocol.WorkspaceListResult
			if err := decodeRPCValue(raw, &value); err != nil {
				return err
			}
			return validateRuntimeWorkspaceExtensions(value)
		}
	case "workspace.get", "workspace.create":
		return func(raw json.RawMessage) error {
			if err := canonical(raw); err != nil {
				return err
			}
			var value protocol.Workspace
			if err := decodeRPCValue(raw, &value); err != nil {
				return err
			}
			return validateRuntimeWorkspaceExtensions(value)
		}
	default:
		return canonical
	}
}

func terminalReadRequestValue(request any) (protocol.TerminalReadRequest, bool) {
	var value protocol.TerminalReadRequest
	if err := decodeClientRequest(request, &value); err != nil {
		return protocol.TerminalReadRequest{}, false
	}
	return value, true
}

func validateClientExtensionRaw(raw json.RawMessage) error {
	if err := validateExtensionValue(raw); err != nil {
		var structured *protocol.Error
		if errors.As(err, &structured) {
			return normalizeProtocolError(structured)
		}
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return nil
}

func validateClientExtensionValue(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return validateClientExtensionRaw(raw)
}

func (c *Client) reserveTerminalFlow(request protocol.TerminalSubscribeRequest) (*clientTerminalFlow, error) {
	key := terminalStreamKey{nativeSession: request.NativeSessionID, streamID: request.StreamID}
	flow := newClientTerminalFlow(request)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminalFlows == nil {
		c.terminalFlows = make(map[terminalStreamKey]*clientTerminalFlow)
	}
	if c.terminalFlows[key] != nil {
		return nil, newProtocolError(protocol.CodeConflict)
	}
	if len(c.terminalFlows) >= c.limits.MaxSubscriptions {
		return nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	c.terminalFlows[key] = flow
	return flow, nil
}

func (c *Client) reserveAttachedTerminalFlow(request protocol.TerminalSubscribeRequest, command protocol.Command) (*clientTerminalFlow, error) {
	raw, err := json.Marshal(command)
	if err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	digest, err := protocol.CommandDigest(raw)
	if err != nil {
		return nil, normalizeProtocolError(err)
	}
	key := terminalStreamKey{nativeSession: request.NativeSessionID, streamID: request.StreamID}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminalFlows == nil {
		c.terminalFlows = make(map[terminalStreamKey]*clientTerminalFlow)
	}
	if existing := c.terminalFlows[key]; existing != nil {
		if existing.retiring {
			return nil, newProtocolError(protocol.CodeConflict)
		}
		sameCommand := existing.attachDigest == digest
		if sameCommand {
			existing.attachPending++
			return existing, nil
		}
		return nil, newProtocolError(protocol.CodeConflict)
	}
	if len(c.terminalFlows) >= c.limits.MaxSubscriptions {
		return nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	flow := newClientTerminalFlow(request)
	flow.attachDigest = digest
	flow.attachPending = 1
	c.terminalFlows[key] = flow
	return flow, nil
}

func newClientTerminalFlow(request protocol.TerminalSubscribeRequest) *clientTerminalFlow {
	return &clientTerminalFlow{
		nativeSession: request.NativeSessionID,
		streamID:      request.StreamID,
		window:        request.WindowBytes,
		remaining:     request.WindowBytes,
		throughOffset: request.AfterOffset,
	}
}

func (f *clientTerminalFlow) bindSubscription(subscriptionID protocol.NativeID) error {
	if f == nil || subscriptionID.Validate() != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return newProtocolError(protocol.CodeConflict)
	}
	if f.subscriptionID != "" && f.subscriptionID != subscriptionID {
		return newProtocolError(protocol.CodeConflict)
	}
	f.subscriptionID = subscriptionID
	return nil
}

func (c *Client) completeAttachedTerminalFlow(flow *clientTerminalFlow, subscriptionID protocol.NativeID, outcome error) error {
	if flow == nil {
		return outcome
	}
	if outcome == nil {
		outcome = flow.bindSubscription(subscriptionID)
	}
	key := terminalStreamKey{nativeSession: flow.nativeSession, streamID: flow.streamID}
	remove := false
	c.mu.Lock()
	if flow.attachPending > 0 {
		flow.attachPending--
	}
	if outcome == nil {
		flow.established = true
	} else if ambiguousTerminalFlowError(outcome) {
		flow.unknown = true
	}
	if outcome != nil && !ambiguousTerminalFlowError(outcome) && flow.attachPending == 0 && !flow.established && !flow.unknown && c.terminalFlows[key] == flow {
		flow.retiring = true
		remove = true
	}
	c.mu.Unlock()
	if remove {
		c.retireTerminalFlow(flow)
	}
	return outcome
}

func ambiguousTerminalFlowError(err error) bool {
	return protocol.IsCode(err, protocol.CodeCancelled) ||
		protocol.IsCode(err, protocol.CodeDeadlineExceeded) ||
		protocol.IsCode(err, protocol.CodeUnavailable) ||
		protocol.IsCode(err, protocol.CodeOutcomeUnknown)
}

func isClientLocalResponseError(err error) bool {
	var local *clientLocalResponseError
	return errors.As(err, &local)
}

func (f *clientTerminalFlow) close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

func (c *Client) releaseTerminalFlow(flow *clientTerminalFlow) {
	c.retireTerminalFlow(flow)
}

func (c *Client) retireTerminalFlow(flow *clientTerminalFlow) {
	if flow == nil {
		return
	}
	key := terminalStreamKey{nativeSession: flow.nativeSession, streamID: flow.streamID}
	c.mu.Lock()
	if c.terminalFlows[key] == flow {
		flow.retiring = true
	}
	c.mu.Unlock()
	flow.close()
	c.mu.Lock()
	if c.terminalFlows[key] == flow {
		delete(c.terminalFlows, key)
	}
	c.mu.Unlock()
}

func (c *Client) terminalFlow(nativeSession protocol.NativeID, streamID string) *clientTerminalFlow {
	c.mu.Lock()
	defer c.mu.Unlock()
	flow := c.terminalFlows[terminalStreamKey{nativeSession: nativeSession, streamID: streamID}]
	if flow != nil && flow.retiring {
		return nil
	}
	return flow
}

func (c *Client) isTerminalFlowActive(flow *clientTerminalFlow) bool {
	if flow == nil {
		return false
	}
	key := terminalStreamKey{nativeSession: flow.nativeSession, streamID: flow.streamID}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminalFlows[key] == flow && !flow.retiring
}

func (c *Client) consumeTerminalChunk(chunk protocol.TerminalChunk) error {
	if err := validateTerminalChunkLimit(chunk, c.currentTerminalMaximum()); err != nil {
		return err
	}
	if chunk.Replayed && !c.canReplay() {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	flow := c.terminalFlow(chunk.NativeSessionID, chunk.StreamID)
	if flow == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return flow.consume(chunk, func() bool { return c.isTerminalFlowActive(flow) })
}

func (f *clientTerminalFlow) consume(chunk protocol.TerminalChunk, active func() bool) error {
	if f == nil || chunk.NativeSessionID != f.nativeSession || chunk.StreamID != f.streamID {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	size, err := terminalChunkSize(chunk)
	if err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || active == nil || !active() {
		return newProtocolError(protocol.CodeConflict)
	}
	nextOffset := f.throughOffset
	if chunk.Offset != nextOffset {
		if !chunk.Truncated || chunk.Offset < nextOffset {
			return newProtocolError(protocol.CodeSequenceConflict)
		}
		nextOffset = chunk.Offset
	}
	if f.sequence != 0 && chunk.Sequence != f.sequence+1 && !chunk.Truncated {
		return newProtocolError(protocol.CodeSequenceConflict)
	}
	if size > f.remaining {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	nextRemaining := f.remaining - size
	if chunk.CreditRemaining != nextRemaining {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	f.remaining = nextRemaining
	f.throughOffset = nextOffset + size
	f.sequence = chunk.Sequence
	return nil
}

func (c *Client) removeTerminalFlowForCommand(command protocol.Command) {
	var subscriptionID protocol.NativeID
	switch command.Capability {
	case "terminal.detach":
		var request TerminalDetachRequest
		if decodeRPCValue(command.Payload, &request) != nil {
			return
		}
		subscriptionID = protocol.NativeID(request.SubscriptionID)
	case "events.unsubscribe":
		var request protocol.EventsUnsubscribeRequest
		if decodeRPCValue(command.Payload, &request) != nil {
			return
		}
		subscriptionID = request.SubscriptionID
	default:
		return
	}
	c.mu.Lock()
	flows := make([]*clientTerminalFlow, 0, len(c.terminalFlows))
	for _, flow := range c.terminalFlows {
		flows = append(flows, flow)
	}
	c.mu.Unlock()
	for _, flow := range flows {
		flow.mu.Lock()
		matches := flow.subscriptionID == subscriptionID
		flow.mu.Unlock()
		if matches {
			c.releaseTerminalFlow(flow)
			return
		}
	}
}

func (c *Client) currentTerminalMaximum() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminalMax
}

func (c *Client) currentMaximum() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maximum
}

func (c *Client) removePending(id string) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *Client) fail(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.readErr = err
		pending := c.pending
		c.pending = make(map[string]chan clientOutcome)
		close(c.done)
		c.mu.Unlock()
		for _, outcome := range pending {
			outcome <- clientOutcome{err: err}
		}
	})
}

// Close closes owned streams and unblocks every pending request.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.closeTransport()
	c.fail(io.EOF)
	return c.transportErr
}

func (c *Client) closeTransport() {
	c.transportOnce.Do(func() {
		for _, closer := range c.closers {
			if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrClosed) {
				c.transportErr = errors.Join(c.transportErr, err)
			}
		}
	})
}

func randomRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "req-" + hex.EncodeToString(value[:]), nil
}
