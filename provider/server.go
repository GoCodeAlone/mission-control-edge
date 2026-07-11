package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

type idempotencyRecord struct {
	digest        protocol.Digest
	done          chan struct{}
	result        json.RawMessage
	err           *protocol.Error
	status        protocol.CommandResultStatus
	reservedBytes uint64
	finalize      sync.Once
	idempotencyID string
	commandID     string
	connectionID  string
}

// Server validates and dispatches one provider's advertised capability set.
// Idempotency state is process-local; durable providers should supply their
// own command-result handler and persist mutation identity before side effects.
type Server struct {
	config   ServerConfig
	handlers HandlerSet
	limits   Limits

	mu               sync.Mutex
	idempotency      map[string]*idempotencyRecord
	commands         map[string]*idempotencyRecord
	idempotencyBytes uint64
	nextConnection   uint64
}

// NewServer constructs a bounded provider server and checks that advertised
// core capabilities have typed handlers (or an SDK-owned built-in).
func NewServer(config ServerConfig, handlers HandlerSet, optionValues ...Option) (*Server, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	options, err := applyOptions(optionValues...)
	if err != nil {
		return nil, err
	}
	advertised := make(map[protocol.CapabilityName]struct{}, len(config.Manifest.Capabilities))
	for capability := range handlers.Extensions {
		if _, core := protocol.Capability(capability); core {
			return nil, fmt.Errorf("core capability %q cannot use an extension handler", capability)
		}
	}
	for _, capability := range config.Manifest.Capabilities {
		advertised[capability.Name] = struct{}{}
		if !handlers.supports(capability.Name) {
			return nil, fmt.Errorf("advertised capability %q has no typed handler", capability.Name)
		}
		if _, core := protocol.Capability(capability.Name); !core {
			extension := handlers.Extensions[capability.Name]
			if capability.Mutating && extension.Mutation == nil || !capability.Mutating && extension.Query == nil {
				return nil, fmt.Errorf("extension capability %q has no matching handler", capability.Name)
			}
		}
	}
	for _, capability := range handlers.advertisedHandlers() {
		if _, ok := advertised[capability]; !ok {
			return nil, fmt.Errorf("handler capability %q is not advertised", capability)
		}
	}
	for _, required := range []protocol.CapabilityName{"provider.initialize", "provider.capabilities"} {
		if _, ok := advertised[required]; !ok {
			return nil, fmt.Errorf("required SDK capability %q is not advertised", required)
		}
	}
	return &Server{
		config:      config,
		handlers:    handlers,
		limits:      options.limits,
		idempotency: make(map[string]*idempotencyRecord),
		commands:    make(map[string]*idempotencyRecord),
	}, nil
}

func (s *Server) reserveConnectionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextConnection++
	return fmt.Sprintf("connection-%d", s.nextConnection)
}

func (s *Server) releaseConnection(connectionID string) {
	s.mu.Lock()
	records := make([]*idempotencyRecord, 0)
	for _, record := range s.idempotency {
		if record.connectionID == connectionID {
			records = append(records, record)
		}
	}
	s.mu.Unlock()
	for _, record := range records {
		s.finalizeMutation(record, protocol.CommandResultOutcomeUnknown, nil, nil, false)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		if s.idempotency[record.idempotencyID] == record {
			delete(s.idempotency, record.idempotencyID)
		}
		if s.commands[record.commandID] == record {
			delete(s.commands, record.commandID)
		}
		if record.reservedBytes <= s.idempotencyBytes {
			s.idempotencyBytes -= record.reservedBytes
		}
		record.reservedBytes = 0
	}
}

// Serve runs over non-owned input/output streams, such as process stdio.
func (s *Server) Serve(ctx context.Context, reader io.Reader, writer io.Writer) error {
	if reader == nil || writer == nil {
		return fmt.Errorf("provider server streams are required")
	}
	return s.serve(ctx, reader, writer, nil)
}

// ServeConn runs over and owns a full-duplex connection.
func (s *Server) ServeConn(ctx context.Context, connection io.ReadWriteCloser) error {
	if connection == nil {
		return fmt.Errorf("provider server connection is required")
	}
	return s.serve(ctx, connection, connection, connection)
}

func (s *Server) serve(parent context.Context, reader io.Reader, writer io.Writer, closer io.Closer) error {
	if parent == nil {
		return fmt.Errorf("provider server context is required")
	}
	ctx, cancel := context.WithCancel(parent)
	connectionID := s.reserveConnectionID()
	connection := &serverConnection{
		server:              s,
		id:                  connectionID,
		ctx:                 ctx,
		cancel:              cancel,
		reader:              bufio.NewReaderSize(reader, 64<<10),
		writer:              newFrameWriter(writer, s.limits.MaxEnvelopeBytes),
		maximum:             s.limits.MaxEnvelopeBytes,
		maximumChunk:        uint64(protocol.MaxTerminalChunkBytes),
		control:             make(chan outboundFrame, s.limits.MaxOutboundQueue),
		data:                make(chan outboundFrame, s.limits.MaxOutboundQueue),
		active:              make(map[string]context.CancelFunc),
		subscriptionCancels: make(map[protocol.NativeID]*subscriptionAdmission),
		terminalStreams:     make(map[string]*subscriptionAdmission),
		sema:                make(chan struct{}, s.limits.MaxInFlightRequests),
	}
	defer s.releaseConnection(connectionID)
	if closer != nil {
		go func() {
			<-ctx.Done()
			_ = closer.Close()
		}()
	}
	writerDone := make(chan error, 1)
	go func() { writerDone <- connection.writeLoop() }()
	connection.startHeartbeat()
	readDone := make(chan error, 1)
	go func() { readDone <- connection.readLoop() }()
	var readErr error
	select {
	case readErr = <-readDone:
	case <-ctx.Done():
		readErr = ctx.Err()
	}
	cancel()
	connection.cancelActive()
	if closer != nil {
		_ = closer.Close()
	}
	shutdownDeadline := time.Now().Add(s.limits.ShutdownTimeout)
	drainDeadline := time.NewTimer(time.Until(shutdownDeadline))
	defer drainDeadline.Stop()
	requestsDone := make(chan struct{})
	go func() {
		connection.requests.Wait()
		close(requestsDone)
	}()
	var drainErr error
	select {
	case <-requestsDone:
	case <-drainDeadline.C:
		drainErr = newProtocolError(protocol.CodeDeadlineExceeded)
	}
	var writeErr error
	if drainErr == nil {
		remaining := time.Until(shutdownDeadline)
		if remaining <= 0 {
			remaining = time.Millisecond
		}
		writeTimer := time.NewTimer(remaining)
		select {
		case writeErr = <-writerDone:
		case <-writeTimer.C:
			writeErr = newProtocolError(protocol.CodeDeadlineExceeded)
		}
		if !writeTimer.Stop() {
			select {
			case <-writeTimer.C:
			default:
			}
		}
	}
	if errors.Is(readErr, io.EOF) || errors.Is(readErr, context.Canceled) || errors.Is(readErr, io.ErrClosedPipe) {
		readErr = nil
	}
	if errors.Is(writeErr, context.Canceled) || errors.Is(writeErr, io.ErrClosedPipe) {
		writeErr = nil
	}
	return errors.Join(readErr, writeErr, drainErr)
}

type outboundFrame struct {
	data    []byte
	maximum uint64
	flushed chan error
	ctx     context.Context
}

type serverConnection struct {
	server *Server
	id     string
	ctx    context.Context
	cancel context.CancelFunc
	reader *bufio.Reader
	writer *frameWriter

	mu                  sync.Mutex
	initialized         bool
	initializing        bool
	maximum             uint64
	maximumChunk        uint64
	replaySupported     bool
	active              map[string]context.CancelFunc
	subscriptionCancels map[protocol.NativeID]*subscriptionAdmission
	terminalStreams     map[string]*subscriptionAdmission
	subscriptions       int
	closing             bool

	control  chan outboundFrame
	data     chan outboundFrame
	sema     chan struct{}
	requests sync.WaitGroup
}

func (c *serverConnection) readLoop() error {
	for {
		frame, err := readFrame(c.reader, c.currentMaximum())
		if err != nil {
			return err
		}
		request, err := decodeRPCRequest(frame, c.currentMaximum())
		if err != nil {
			return err
		}
		if request.isNotification() {
			if err := c.handleNotification(request); err != nil {
				return err
			}
			continue
		}
		requestCtx, requestCancel := context.WithCancel(c.ctx)
		if err := c.reserveRequest(request.ID, requestCancel); err != nil {
			requestCancel()
			if sendErr := c.sendError(request.ID, err); sendErr != nil {
				return sendErr
			}
			continue
		}
		select {
		case c.sema <- struct{}{}:
		case <-c.ctx.Done():
			requestCancel()
			c.releaseRequest(request.ID)
			return c.ctx.Err()
		default:
			requestCancel()
			c.releaseRequest(request.ID)
			if err := c.sendError(request.ID, newProtocolError(protocol.CodeResourceExhausted)); err != nil {
				return err
			}
			continue
		}
		c.requests.Add(1)
		go func(requestCtx context.Context, requestCancel context.CancelFunc, raw json.RawMessage, rpcRequest rpcRequest) {
			defer c.requests.Done()
			defer func() { <-c.sema }()
			c.processRequest(requestCtx, requestCancel, raw, rpcRequest)
		}(requestCtx, requestCancel, append(json.RawMessage(nil), request.Params[0]...), request)
	}
}

func (c *serverConnection) processRequest(ctx context.Context, cancel context.CancelFunc, raw json.RawMessage, request rpcRequest) {
	defer cancel()
	defer c.releaseRequest(request.ID)

	result, action, shutdown, err := c.execute(ctx, request.Method, raw)
	responseCtx := ctx
	var responseCancel context.CancelFunc
	if action != nil {
		if action.ctx != nil {
			responseCtx = action.ctx
		}
		responseCancel = action.cancel
		defer func() {
			if action != nil && action.rollback != nil {
				action.rollback()
			}
		}()
	}
	if responseCancel != nil {
		defer responseCancel()
	}
	if err == nil && responseCtx.Err() != nil {
		err = newProtocolError(errorCode(responseCtx.Err()))
	}
	var frame []byte
	responseMaximum := c.currentMaximum()
	commitAction := err == nil
	if err != nil {
		frame, err = marshalErrorResponse(request.ID, err, responseMaximum)
	} else {
		frame, err = marshalResponse(request.ID, result, responseMaximum)
		if err != nil {
			commitAction = false
			frame, err = marshalErrorResponse(request.ID, err, responseMaximum)
		}
	}
	if err != nil {
		c.cancel()
		return
	}
	// A successful handler can still produce an acknowledgement that cannot fit
	// the negotiated envelope. Roll back before the error is observable so an
	// immediate retry cannot collide with provisional subscription state.
	if !commitAction && action != nil {
		if action.rollback != nil {
			action.rollback()
		}
		action = nil
	}
	if commitAction && action != nil && action.prepare != nil {
		action.prepare()
	}
	frameCtx := responseCtx
	if !commitAction {
		frameCtx = ctx
	}
	flushed := make(chan error, 1)
	if err := c.enqueueControl(outboundFrame{data: frame, maximum: responseMaximum, flushed: flushed, ctx: frameCtx}); err != nil {
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			c.cancel()
		}
		return
	}
	handleFlush := func(err error) bool {
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				c.cancel()
			}
			return false
		}
		return true
	}
	flushedSuccessfully := false
	select {
	case flushErr := <-flushed:
		if !handleFlush(flushErr) {
			return
		}
		flushedSuccessfully = true
	default:
	}
	if !flushedSuccessfully {
		select {
		case flushErr := <-flushed:
			if !handleFlush(flushErr) {
				return
			}
			flushedSuccessfully = true
		case <-frameCtx.Done():
			select {
			case flushErr := <-flushed:
				if !handleFlush(flushErr) {
					return
				}
				flushedSuccessfully = true
			default:
				if action != nil {
					c.cancel()
				}
			}
		case <-c.ctx.Done():
			return
		}
	}
	if !flushedSuccessfully {
		return
	}
	if commitAction && action != nil {
		if action.commit != nil {
			action.commit()
		}
		action = nil
	}
	if shutdown && commitAction {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()
		c.cancel()
	}
}

func (c *serverConnection) execute(ctx context.Context, method string, raw json.RawMessage) (any, *responseAction, bool, error) {
	if ctx.Err() != nil {
		return nil, nil, false, newProtocolError(errorCode(ctx.Err()))
	}
	capability := protocol.CapabilityName(method)
	if capability == "provider.initialize" {
		if !c.beginInitialization() {
			return nil, nil, false, newProtocolError(protocol.CodeConflict)
		}
		var request protocol.ProviderInitializeRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			c.abortInitialization()
			return nil, nil, false, err
		}
		result, err := c.initialize(ctx, request, raw)
		if err != nil {
			c.abortInitialization()
			return nil, nil, false, err
		}
		negotiatedMaximum := min(c.server.limits.MaxEnvelopeBytes, result.MaximumMessageBytes)
		negotiatedChunk := result.MaximumChunkBytes
		negotiatedReplay := result.ReplaySupported
		action := &responseAction{
			prepare: func() {
				c.mu.Lock()
				c.maximum = negotiatedMaximum
				c.maximumChunk = negotiatedChunk
				c.replaySupported = negotiatedReplay
				c.writer.mu.Lock()
				c.writer.maximumBytes = negotiatedMaximum
				c.writer.mu.Unlock()
				c.initialized = true
				c.initializing = false
				c.mu.Unlock()
			},
			rollback: func() {
				c.mu.Lock()
				c.maximum = c.server.limits.MaxEnvelopeBytes
				c.maximumChunk = uint64(protocol.MaxTerminalChunkBytes)
				c.replaySupported = false
				c.writer.mu.Lock()
				c.writer.maximumBytes = c.server.limits.MaxEnvelopeBytes
				c.writer.mu.Unlock()
				c.initialized = false
				c.initializing = false
				c.mu.Unlock()
			},
		}
		return result, action, false, nil
	}
	if !c.isInitialized() {
		return nil, nil, false, newProtocolError(protocol.CodeUnauthenticated)
	}
	descriptor, advertised := c.server.config.Manifest.Capability(capability)
	if !advertised {
		return nil, nil, false, notSupported(capability, manifestCapabilities(c.server.config.Manifest))
	}
	if !descriptor.Mutating {
		if err := validateReplayRequest(capability, raw, c.canReplay()); err != nil {
			return nil, nil, false, err
		}
	}
	dispatchCtx := ctx
	var queryAdmission *subscriptionAdmission
	if isSubscriptionCapability(capability) && !descriptor.Mutating {
		var err error
		if capability == "terminal.subscribe" {
			var request protocol.TerminalSubscribeRequest
			if err = decodeRPCValue(raw, &request); err == nil {
				queryAdmission, err = c.beginTerminalSubscription(ctx, request)
			}
		} else {
			queryAdmission, err = c.beginSubscription(ctx)
		}
		if err != nil {
			return nil, nil, false, err
		}
		defer func() {
			if queryAdmission != nil {
				queryAdmission.cleanup()
			}
		}()
		dispatchCtx = queryAdmission.setup
	}
	if dispatchCtx.Err() != nil {
		return nil, nil, false, newProtocolError(errorCode(dispatchCtx.Err()))
	}
	if capability == "provider.capabilities" {
		var request protocol.ProviderCapabilitiesRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return nil, nil, false, err
		}
		result := protocol.ProviderCapabilitiesResult{
			ProviderID: c.server.config.Manifest.ID, Roles: append([]protocol.ProviderRole(nil), c.server.config.Manifest.Roles...),
			Capabilities: append([]protocol.CapabilityDescriptor(nil), c.server.config.Manifest.Capabilities...),
		}
		if c.server.handlers.Provider.Capabilities != nil {
			value, err := c.server.handlers.dispatch(ctx, capability, nil, raw)
			if err != nil {
				return nil, nil, false, err
			}
			custom, ok := value.(protocol.ProviderCapabilitiesResult)
			if !ok || !equalJSON(custom, result) {
				return nil, nil, false, newProtocolError(protocol.CodeConflict)
			}
			result = custom
		}
		return result, nil, false, nil
	}
	if capability == "command.get_result" && c.server.handlers.Provider.Commands.GetResult == nil {
		var request protocol.CommandGetResultRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return nil, nil, false, err
		}
		result, err := c.server.commandResult(request.CommandID)
		return result, nil, false, err
	}
	if descriptor.Mutating {
		var command protocol.Command
		if err := decodeRPCValue(raw, &command); err != nil {
			return nil, nil, false, err
		}
		if command.Capability != capability {
			return nil, nil, false, newProtocolError(protocol.CodeInvalidArgument)
		}
		if err := command.ValidateAgainstManifest(c.server.config.Manifest); err != nil {
			return nil, nil, false, err
		}
		if !command.Deadline.After(time.Now()) {
			return nil, nil, false, newProtocolError(protocol.CodeDeadlineExceeded)
		}
		commandCtx, cancel := context.WithDeadline(ctx, command.Deadline)
		handedOff := false
		defer func() {
			if !handedOff {
				cancel()
			}
		}()
		meta, err := newMutationMeta(command, raw)
		if err != nil {
			return nil, nil, false, err
		}
		if err := validateReplayRequest(capability, meta.Payload, c.canReplay()); err != nil {
			return nil, nil, false, err
		}
		if capability == "terminal.send_input" {
			var request protocol.TerminalInputRequest
			if err := decodeRPCValue(meta.Payload, &request); err != nil {
				return nil, nil, false, err
			}
			size, err := terminalDataSize(request.Encoding, request.Data)
			if err != nil {
				return nil, nil, false, newProtocolError(protocol.CodeInvalidArgument)
			}
			if size > c.currentMaximumChunk() {
				return nil, nil, false, newProtocolError(protocol.CodeMessageTooLarge)
			}
		}
		var admission func(context.Context) (*subscriptionAdmission, error)
		if capability == "terminal.attach" {
			var request protocol.TerminalSubscribeRequest
			if err := decodeRPCValue(meta.Payload, &request); err != nil {
				return nil, nil, false, err
			}
			admission = func(setup context.Context) (*subscriptionAdmission, error) {
				return c.beginTerminalSubscription(setup, request)
			}
		}
		value, action, err := c.server.executeMutation(commandCtx, c.id, meta, c.currentMaximum(), admission)
		if err != nil {
			return nil, nil, false, err
		}
		if action != nil {
			switch capability {
			case "events.unsubscribe":
				var request protocol.EventsUnsubscribeRequest
				if err := decodeRPCValue(meta.Payload, &request); err != nil {
					return nil, nil, false, err
				}
				prior := action.commit
				action.commit = func() {
					c.cancelSubscription(protocol.NativeID(request.SubscriptionID))
					if prior != nil {
						prior()
					}
				}
			case "terminal.detach":
				var request TerminalDetachRequest
				if err := decodeRPCValue(meta.Payload, &request); err != nil {
					return nil, nil, false, err
				}
				prior := action.commit
				action.commit = func() {
					c.cancelSubscription(protocol.NativeID(request.SubscriptionID))
					if prior != nil {
						prior()
					}
				}
			}
		}
		if action == nil {
			action = &responseAction{}
		}
		action.ctx = commandCtx
		action.cancel = cancel
		handedOff = true
		return subscriptionWireResult(value), action, capability == "provider.shutdown", nil
	}
	value, err := c.server.handlers.dispatch(dispatchCtx, capability, nil, raw)
	if err != nil {
		return nil, nil, false, err
	}
	if capability == "terminal.read" {
		chunk, ok := value.(protocol.TerminalChunk)
		if !ok {
			return nil, nil, false, newProtocolError(protocol.CodeUnavailable)
		}
		var request protocol.TerminalReadRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return nil, nil, false, err
		}
		if err := validateTerminalReadChunk(request, chunk, c.currentMaximumChunk(), c.canReplay()); err != nil {
			return nil, nil, false, err
		}
	}
	if ctx.Err() != nil {
		return nil, nil, false, newProtocolError(errorCode(ctx.Err()))
	}
	action, err := queryAdmission.prepare(value)
	if err != nil {
		return nil, nil, false, err
	}
	queryAdmission = nil
	return subscriptionWireResult(value), action, false, nil
}

func (c *serverConnection) initialize(ctx context.Context, request protocol.ProviderInitializeRequest, raw json.RawMessage) (protocol.ProviderInitializeResult, error) {
	if c.server.handlers.Provider.Initialize != nil {
		value, err := c.server.handlers.dispatch(ctx, "provider.initialize", nil, raw)
		if err != nil {
			return protocol.ProviderInitializeResult{}, err
		}
		result, ok := value.(protocol.ProviderInitializeResult)
		if !ok {
			return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeUnavailable)
		}
		if err := protocol.ValidateProviderNegotiation(request, result); err != nil {
			return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
		}
		if err := c.validateCustomNegotiation(result); err != nil {
			return protocol.ProviderInitializeResult{}, err
		}
		return result, nil
	}
	if err := request.Validate(); err != nil {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	if !slices.Contains(request.SupportedProtocolVersions, protocol.Version) {
		return protocol.ProviderInitializeResult{}, notSupported("provider.initialize", manifestCapabilities(c.server.config.Manifest))
	}
	authentication := ""
	for _, supported := range c.server.config.AuthenticationModes {
		if slices.Contains(request.AuthenticationModes, supported) {
			authentication = supported
			break
		}
	}
	if authentication == "" {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeUnauthenticated)
	}
	features := make([]string, 0, len(c.server.config.ExperimentalFeatures))
	for _, feature := range c.server.config.ExperimentalFeatures {
		if slices.Contains(request.ExperimentalFeatures, feature) {
			features = append(features, feature)
		}
	}
	maximumMessageBytes := min(request.MaximumMessageBytes, c.server.limits.MaxEnvelopeBytes)
	result := protocol.ProviderInitializeResult{
		ProtocolVersion:      protocol.Version,
		Manifest:             c.server.config.Manifest,
		NativeRuntimeVersion: c.server.config.NativeRuntimeVersion,
		MaximumMessageBytes:  maximumMessageBytes,
		MaximumChunkBytes:    min(request.MaximumChunkBytes, uint64(protocol.MaxTerminalChunkBytes), maximumMessageBytes),
		ReplaySupported:      request.ReplaySupported && c.server.config.ReplaySupported,
		AuthenticationMode:   authentication,
		ExperimentalFeatures: features,
	}
	if err := protocol.ValidateProviderNegotiation(request, result); err != nil {
		return protocol.ProviderInitializeResult{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	return result, nil
}

func (c *serverConnection) validateCustomNegotiation(result protocol.ProviderInitializeResult) error {
	actualManifest, actualErr := json.Marshal(result.Manifest)
	expectedManifest, expectedErr := json.Marshal(c.server.config.Manifest)
	if actualErr != nil || expectedErr != nil || !bytes.Equal(actualManifest, expectedManifest) {
		return newProtocolError(protocol.CodeConflict)
	}
	if result.MaximumMessageBytes > c.server.limits.MaxEnvelopeBytes || result.MaximumChunkBytes > uint64(protocol.MaxTerminalChunkBytes) {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if !slices.Contains(c.server.config.AuthenticationModes, result.AuthenticationMode) {
		return newProtocolError(protocol.CodeUnauthenticated)
	}
	if result.ReplaySupported && !c.server.config.ReplaySupported {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	for _, feature := range result.ExperimentalFeatures {
		if !slices.Contains(c.server.config.ExperimentalFeatures, feature) {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	}
	return nil
}

func equalJSON(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func decodeRPCValue(raw json.RawMessage, destination any) error {
	request := rpcRequest{JSONRPC: jsonRPCVersion, ID: "validation-request", Method: "validation", Params: []json.RawMessage{raw}}
	if err := decodeRPCParam(request, destination); err != nil {
		return err
	}
	// Handler decoding is closed; apply the same rule to SDK-owned built-ins.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return protocol.Decode(raw, destination)
}

func (s *Server) executeMutation(ctx context.Context, connectionID string, meta MutationMeta, maximumBytes uint64, admit func(context.Context) (*subscriptionAdmission, error)) (any, *responseAction, error) {
	idempotencyID, commandID, scopedConnection := mutationRecordIDs(connectionID, meta)
	s.mu.Lock()
	if prior := s.idempotency[idempotencyID]; prior != nil {
		if prior.digest != meta.CommandDigest {
			s.mu.Unlock()
			return nil, nil, newProtocolError(protocol.CodeConflict)
		}
		done := prior.done
		s.mu.Unlock()
		select {
		case <-done:
			switch prior.status {
			case protocol.CommandResultSucceeded:
				return append(json.RawMessage(nil), prior.result...), nil, nil
			case protocol.CommandResultFailed:
				value := *prior.err
				return nil, nil, &value
			case protocol.CommandResultOutcomeUnknown:
				return nil, nil, newProtocolError(protocol.CodeOutcomeUnknown)
			default:
				return nil, nil, newProtocolError(protocol.CodeUnavailable)
			}
		case <-ctx.Done():
			return nil, nil, newProtocolError(errorCode(ctx.Err()))
		}
	}
	if existing := s.commands[commandID]; existing != nil {
		s.mu.Unlock()
		return nil, nil, newProtocolError(protocol.CodeConflict)
	}
	if len(s.idempotency) >= s.limits.MaxIdempotencyEntries {
		s.mu.Unlock()
		return nil, nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	if maximumBytes > s.limits.MaxIdempotencyBytes-s.idempotencyBytes {
		s.mu.Unlock()
		return nil, nil, newProtocolError(protocol.CodeResourceExhausted)
	}
	record := &idempotencyRecord{
		digest:        meta.CommandDigest,
		done:          make(chan struct{}),
		status:        protocol.CommandResultPending,
		reservedBytes: maximumBytes,
		idempotencyID: idempotencyID,
		commandID:     commandID,
		connectionID:  scopedConnection,
	}
	s.idempotency[idempotencyID] = record
	s.commands[commandID] = record
	s.idempotencyBytes += maximumBytes
	s.mu.Unlock()

	var admission *subscriptionAdmission
	handlerCtx := ctx
	var err error
	admissionFailed := false
	if admit != nil {
		admission, err = admit(ctx)
		admissionFailed = err != nil
		if err == nil {
			handlerCtx = admission.setup
		}
	}
	var value any
	if err == nil && handlerCtx.Err() != nil {
		err = newProtocolError(errorCode(handlerCtx.Err()))
	}
	if err == nil {
		value, err = s.handlers.dispatch(handlerCtx, meta.Capability, &meta, meta.Payload)
	}
	if err != nil {
		if admission != nil {
			admission.cleanup()
		}
		var postResult *postMutationResultError
		if errors.As(err, &postResult) {
			s.finalizeMutation(record, protocol.CommandResultOutcomeUnknown, nil, nil, false)
			return nil, nil, newProtocolError(protocol.CodeOutcomeUnknown)
		}
		structured := normalizeProtocolError(err)
		s.finalizeMutation(record, protocol.CommandResultFailed, nil, structured, admissionFailed)
		return nil, nil, structured
	}
	if ctx.Err() != nil {
		if admission != nil {
			admission.cleanup()
		}
		s.finalizeMutation(record, protocol.CommandResultOutcomeUnknown, nil, nil, false)
		return nil, nil, newProtocolError(protocol.CodeOutcomeUnknown)
	}
	var action *responseAction
	if admission != nil {
		action, err = admission.prepare(value)
	}
	var raw json.RawMessage
	if err == nil {
		encoded, marshalErr := json.Marshal(subscriptionWireResult(value))
		if marshalErr != nil {
			err = newProtocolError(protocol.CodeUnavailable)
		} else {
			raw = encoded
			if _, marshalErr = marshalResponse(strings.Repeat("r", 256), json.RawMessage(raw), maximumBytes); marshalErr != nil {
				err = marshalErr
			}
		}
	}
	if err != nil {
		if action != nil && action.rollback != nil {
			action.rollback()
		} else if admission != nil {
			admission.cleanup()
		}
		// The handler returned success, so encoding or subscription-finalization
		// failures cannot truthfully be reported as a failed operation.
		s.finalizeMutation(record, protocol.CommandResultOutcomeUnknown, nil, nil, false)
		return nil, nil, newProtocolError(protocol.CodeOutcomeUnknown)
	}
	providerAction := action
	return value, &responseAction{
		prepare: func() {
			if providerAction != nil && providerAction.prepare != nil {
				providerAction.prepare()
			}
		},
		commit: func() {
			if providerAction != nil && providerAction.commit != nil {
				providerAction.commit()
			}
			s.finalizeMutation(record, protocol.CommandResultSucceeded, raw, nil, false)
		},
		rollback: func() {
			if providerAction != nil && providerAction.rollback != nil {
				providerAction.rollback()
			}
			s.finalizeMutation(record, protocol.CommandResultOutcomeUnknown, nil, nil, false)
		},
	}, nil
}

func mutationRecordIDs(connectionID string, meta MutationMeta) (string, string, string) {
	if meta.Capability == "terminal.attach" {
		return string(meta.Capability) + "\x00" + connectionID + "\x00" + meta.IdempotencyKey,
			meta.CommandID, connectionID
	}
	return string(meta.Capability) + "\x00" + meta.IdempotencyKey, meta.CommandID, ""
}

func (s *Server) finalizeMutation(record *idempotencyRecord, status protocol.CommandResultStatus, result json.RawMessage, failure *protocol.Error, remove bool) {
	record.finalize.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		record.status = status
		record.result = append(json.RawMessage(nil), result...)
		if failure != nil {
			value := *failure
			record.err = &value
		}
		retained := uint64(0)
		if status == protocol.CommandResultSucceeded {
			retained = uint64(len(record.result))
		}
		if retained <= record.reservedBytes {
			s.idempotencyBytes -= record.reservedBytes - retained
		}
		record.reservedBytes = retained
		if remove {
			if s.idempotency[record.idempotencyID] == record {
				delete(s.idempotency, record.idempotencyID)
			}
			if s.commands[record.commandID] == record {
				delete(s.commands, record.commandID)
			}
			if record.reservedBytes <= s.idempotencyBytes {
				s.idempotencyBytes -= record.reservedBytes
			}
			record.reservedBytes = 0
		}
		close(record.done)
	})
}

func (s *Server) commandResult(commandID string) (protocol.CommandResult, error) {
	s.mu.Lock()
	record := s.commands[commandID]
	s.mu.Unlock()
	if record == nil {
		return protocol.CommandResult{}, newProtocolError(protocol.CodeUnavailable)
	}
	select {
	case <-record.done:
		result := protocol.CommandResult{CommandID: commandID, ObservedAt: time.Now().UTC()}
		switch record.status {
		case protocol.CommandResultFailed:
			value := *record.err
			result.Status = protocol.CommandResultFailed
			result.Error = &value
		case protocol.CommandResultSucceeded:
			result.Status = protocol.CommandResultSucceeded
			result.Result = append(json.RawMessage(nil), record.result...)
		case protocol.CommandResultOutcomeUnknown:
			result.Status = protocol.CommandResultOutcomeUnknown
		default:
			result.Status = protocol.CommandResultPending
		}
		return result, nil
	default:
		return protocol.CommandResult{CommandID: commandID, Status: protocol.CommandResultPending, ObservedAt: time.Now().UTC()}, nil
	}
}

func subscriptionWireResult(value any) any {
	switch typed := value.(type) {
	case EventSubscription:
		return typed.Result
	case TerminalSubscription:
		return typed.Result
	case TopologySubscription:
		return typed.Result
	default:
		return value
	}
}

func isSubscriptionCapability(capability protocol.CapabilityName) bool {
	switch capability {
	case "events.subscribe", "terminal.subscribe", "terminal.attach", "topology.subscribe":
		return true
	default:
		return false
	}
}

func validateReplayRequest(capability protocol.CapabilityName, raw json.RawMessage, replaySupported bool) error {
	if replaySupported {
		return nil
	}
	switch capability {
	case "terminal.read":
		var request protocol.TerminalReadRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return err
		}
		if request.AfterOffset > 0 {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	case "terminal.subscribe", "terminal.attach":
		var request protocol.TerminalSubscribeRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return err
		}
		if request.AfterOffset > 0 {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	case "events.subscribe":
		var request protocol.EventsSubscribeRequest
		if err := decodeRPCValue(raw, &request); err != nil {
			return err
		}
		for _, cursor := range request.Cursors {
			if cursor.AfterSequence > 0 {
				return newProtocolError(protocol.CodeInvalidArgument)
			}
		}
	}
	return nil
}

func manifestCapabilities(manifest protocol.ProviderManifest) []protocol.CapabilityName {
	result := make([]protocol.CapabilityName, 0, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		result = append(result, capability.Name)
	}
	slices.Sort(result)
	return result
}

func (c *serverConnection) handleNotification(request rpcRequest) error {
	switch request.Method {
	case NotificationCancel:
		var cancellation CancelRequest
		if err := decodeRPCParam(request, &cancellation); err != nil {
			return err
		}
		c.mu.Lock()
		cancel := c.active[cancellation.RequestID]
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		return nil
	case NotificationHeartbeat:
		var heartbeat Heartbeat
		return decodeRPCParam(request, &heartbeat)
	case NotificationTerminalCredit:
		var credit protocol.TerminalCredit
		if err := decodeRPCParam(request, &credit); err != nil {
			return err
		}
		return c.applyTerminalCredit(credit)
	default:
		return notSupported(protocol.CapabilityName(request.Method), manifestCapabilities(c.server.config.Manifest))
	}
}

func notSupported(capability protocol.CapabilityName, advertised []protocol.CapabilityName) error {
	err := protocol.NotSupported(capability, advertised)
	var structured *protocol.Error
	if !errors.As(err, &structured) || structured.Validate() != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return err
}

func (c *serverConnection) reserveRequest(id string, cancel context.CancelFunc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return newProtocolError(protocol.CodeUnavailable)
	}
	if _, duplicate := c.active[id]; duplicate {
		return newProtocolError(protocol.CodeConflict)
	}
	c.active[id] = cancel
	return nil
}

func (c *serverConnection) releaseRequest(id string) {
	c.mu.Lock()
	delete(c.active, id)
	c.mu.Unlock()
}

func (c *serverConnection) cancelActive() {
	c.mu.Lock()
	active := make([]context.CancelFunc, 0, len(c.active))
	for _, cancel := range c.active {
		active = append(active, cancel)
	}
	c.mu.Unlock()
	for _, cancel := range active {
		cancel()
	}
}

func (c *serverConnection) isInitialized() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.initialized
}

func (c *serverConnection) beginInitialization() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initialized || c.initializing {
		return false
	}
	c.initializing = true
	return true
}

func (c *serverConnection) abortInitialization() {
	c.mu.Lock()
	c.initializing = false
	c.mu.Unlock()
}

func (c *serverConnection) currentMaximum() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maximum
}

func (c *serverConnection) currentMaximumChunk() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maximumChunk
}

func (c *serverConnection) canReplay() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.replaySupported
}

func (c *serverConnection) sendError(id string, err error) error {
	frame, marshalErr := marshalErrorResponse(id, err, c.currentMaximum())
	if marshalErr != nil {
		return marshalErr
	}
	return c.enqueueControl(outboundFrame{data: frame})
}

func (c *serverConnection) enqueueControl(frame outboundFrame) error {
	if frame.ctx != nil {
		select {
		case c.control <- frame:
			return nil
		case <-frame.ctx.Done():
			return frame.ctx.Err()
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
	select {
	case c.control <- frame:
		return nil
	case <-c.ctx.Done():
		return c.ctx.Err()
	}
}

func (c *serverConnection) enqueueData(frame outboundFrame) error {
	select {
	case c.data <- frame:
		return nil
	default:
		return newProtocolError(protocol.CodeResourceExhausted)
	}
}

func (c *serverConnection) writeLoop() error {
	for {
		select {
		case frame := <-c.control:
			if err := c.writeOutbound(frame); err != nil {
				return err
			}
			continue
		default:
		}
		select {
		case frame := <-c.control:
			if err := c.writeOutbound(frame); err != nil {
				return err
			}
		case frame := <-c.data:
			if err := c.writeOutbound(frame); err != nil {
				return err
			}
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}
}

func (c *serverConnection) writeOutbound(frame outboundFrame) error {
	if frame.ctx != nil {
		if err := frame.ctx.Err(); err != nil {
			if frame.flushed != nil {
				frame.flushed <- err
			}
			return nil
		}
	}
	maximum := frame.maximum
	if maximum == 0 {
		maximum = c.currentMaximum()
	}
	err := c.writer.writeWithMaximum(frame.data, maximum)
	if frame.flushed != nil {
		frame.flushed <- err
	}
	return err
}

func (c *serverConnection) startHeartbeat() {
	go func() {
		ticker := time.NewTicker(c.server.limits.HeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case observed := <-ticker.C:
				if !c.isInitialized() {
					continue
				}
				if err := c.sendHeartbeat(observed.UTC()); err != nil {
					c.cancel()
					return
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()
}

func (c *serverConnection) sendHeartbeat(observedAt time.Time) error {
	frame, err := marshalNotification(NotificationHeartbeat, Heartbeat{ObservedAt: observedAt}, c.currentMaximum())
	if err != nil {
		return err
	}
	if err := c.enqueueData(outboundFrame{data: frame}); err != nil && !protocol.IsCode(err, protocol.CodeResourceExhausted) {
		return err
	}
	return nil
}
