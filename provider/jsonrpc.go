package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const (
	jsonRPCVersion = "2.0"

	// NotificationEvent carries a canonical provider event.
	NotificationEvent = "$mc/event"
	// NotificationTerminalChunk carries replayed or live terminal output.
	NotificationTerminalChunk = "$mc/terminal.chunk"
	// NotificationTopologySnapshot carries replayed or live workspace topology.
	NotificationTopologySnapshot = "$mc/topology.snapshot"
	// NotificationHeartbeat reports that the peer's transport loop is alive.
	NotificationHeartbeat = "$mc/heartbeat"
	// NotificationCancel cancels an in-flight request by its string ID.
	NotificationCancel = "$mc/cancel"
	// NotificationTerminalCredit replenishes a terminal subscription window.
	NotificationTerminalCredit = "$mc/terminal.credit" // #nosec G101 -- public flow-control method name, not a credential.
)

const (
	rpcCodeInvalidRequest = -32600
	rpcCodeMethodNotFound = -32601
	rpcCodeInvalidParams  = -32602
	rpcCodeInternalError  = -32603
	rpcCodeServerError    = -32000
)

// rpcRequest uses the one-object, by-position parameter shape published by the
// protocol OpenRPC document. An empty ID denotes a notification; request IDs
// are otherwise non-empty strings.
type rpcRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      string            `json:"id,omitempty"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError keeps the JSON-RPC error envelope content-free. All semantics live
// in the validated protocol.Error data object rather than an arbitrary native
// error string.
type rpcError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    protocol.Error `json:"data"`
}

func (e *rpcError) Error() string {
	if e == nil {
		return ""
	}
	return e.Data.Error()
}

func (e *rpcError) protocolError() error {
	if e == nil {
		return nil
	}
	value := e.Data
	value.AdvertisedCapabilities = append([]protocol.CapabilityName(nil), value.AdvertisedCapabilities...)
	return &value
}

func (e rpcError) validate() error {
	if err := e.Data.Validate(); err != nil {
		return fmt.Errorf("JSON-RPC error data is invalid")
	}
	if e.Message != e.Data.Message {
		return fmt.Errorf("JSON-RPC error message is not canonical")
	}
	expected := rpcCodeServerError
	switch e.Data.Code {
	case protocol.CodeInvalidArgument, protocol.CodeMessageTooLarge:
		expected = rpcCodeInvalidParams
	case protocol.CodeNotSupported:
		expected = rpcCodeMethodNotFound
	}
	if e.Code != expected {
		return fmt.Errorf("JSON-RPC error code is invalid")
	}
	return nil
}

func (r rpcRequest) isNotification() bool { return r.ID == "" }

func (r rpcRequest) validate() error {
	if r.JSONRPC != jsonRPCVersion {
		return fmt.Errorf("JSON-RPC version is invalid")
	}
	if r.ID != "" {
		if err := validateWireToken("request ID", r.ID); err != nil {
			return err
		}
	}
	if err := validateWireToken("method", r.Method); err != nil {
		return err
	}
	if len(r.Params) != 1 {
		return fmt.Errorf("JSON-RPC params must contain exactly one value")
	}
	return validateObject(r.Params[0])
}

func (r rpcResponse) validate() error {
	if r.JSONRPC != jsonRPCVersion {
		return fmt.Errorf("JSON-RPC version is invalid")
	}
	if err := validateWireToken("response ID", r.ID); err != nil {
		return err
	}
	if (len(r.Result) == 0) == (r.Error == nil) {
		return fmt.Errorf("JSON-RPC response must contain exactly one outcome")
	}
	if r.Error != nil {
		return r.Error.validate()
	}
	return validateJSON(r.Result)
}

func validateWireToken(name, value string) error {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	return nil
}

func validateJSON(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("JSON value is required")
	}
	var value any
	if err := protocol.Decode(data, &value); err != nil {
		return err
	}
	if value == nil {
		return fmt.Errorf("JSON value cannot be null")
	}
	return nil
}

func validateObject(data []byte) error {
	if err := validateJSON(data); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil {
		return fmt.Errorf("JSON-RPC parameter must be an object")
	}
	return nil
}

func marshalRequest(id, method string, parameter any, maximumBytes uint64) ([]byte, error) {
	if err := validateWireToken("request ID", id); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return marshalRPCRequest(rpcRequest{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Method:  method,
		Params:  []json.RawMessage{mustMarshalParameter(parameter)},
	}, parameter, maximumBytes)
}

func marshalNotification(method string, parameter any, maximumBytes uint64) ([]byte, error) {
	return marshalRPCRequest(rpcRequest{
		JSONRPC: jsonRPCVersion,
		Method:  method,
		Params:  []json.RawMessage{mustMarshalParameter(parameter)},
	}, parameter, maximumBytes)
}

// marshalRPCRequest accepts the original parameter separately so validation
// can happen before encoding. A failed preliminary marshal is represented by a
// nil Params element and is rejected without exposing the marshal error.
func marshalRPCRequest(request rpcRequest, parameter any, maximumBytes uint64) ([]byte, error) {
	if len(request.Params) != 1 || len(request.Params[0]) == 0 {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateOutbound(parameter); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := request.validate(); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return marshalEnvelope(request, maximumBytes)
}

func marshalResponse(id string, result any, maximumBytes uint64) ([]byte, error) {
	if err := validateOutbound(result); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	response := rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Result: raw}
	if err := response.validate(); err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return marshalEnvelope(response, maximumBytes)
}

func marshalErrorResponse(id string, err error, maximumBytes uint64) ([]byte, error) {
	response := rpcResponse{JSONRPC: jsonRPCVersion, ID: id, Error: rpcErrorFrom(err)}
	if validateErr := response.validate(); validateErr != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return marshalEnvelope(response, maximumBytes)
}

func marshalEnvelope(value any, maximumBytes uint64) ([]byte, error) {
	if err := validateMaximumBytes(maximumBytes); err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if uint64(len(data)) > maximumBytes {
		return nil, newProtocolError(protocol.CodeMessageTooLarge)
	}
	if bytes.IndexByte(data, '\n') >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	return data, nil
}

func decodeRPCRequest(data []byte, maximumBytes uint64) (rpcRequest, error) {
	if err := validateEnvelope(data, maximumBytes); err != nil {
		return rpcRequest{}, err
	}
	var fields map[string]json.RawMessage
	if err := protocol.Decode(data, &fields); err != nil {
		return rpcRequest{}, err
	}
	if err := validateEnvelopeFields(fields, []string{"jsonrpc", "method", "params"}, []string{"jsonrpc", "id", "method", "params"}); err != nil {
		return rpcRequest{}, err
	}
	var request rpcRequest
	if err := protocol.Decode(data, &request); err != nil {
		return rpcRequest{}, err
	}
	if rawID, present := fields["id"]; present {
		if err := json.Unmarshal(rawID, &request.ID); err != nil || request.ID == "" {
			return rpcRequest{}, newProtocolError(protocol.CodeInvalidArgument)
		}
	}
	if err := request.validate(); err != nil {
		return rpcRequest{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	return request, nil
}

func decodeRPCResponse(data []byte, maximumBytes uint64) (rpcResponse, error) {
	if err := validateEnvelope(data, maximumBytes); err != nil {
		return rpcResponse{}, err
	}
	var fields map[string]json.RawMessage
	if err := protocol.Decode(data, &fields); err != nil {
		return rpcResponse{}, err
	}
	if err := validateEnvelopeFields(fields, []string{"jsonrpc", "id"}, []string{"jsonrpc", "id", "result", "error"}); err != nil {
		return rpcResponse{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	var response rpcResponse
	if err := protocol.Decode(data, &response); err != nil {
		return rpcResponse{}, err
	}
	if err := response.validate(); err != nil {
		return rpcResponse{}, newProtocolError(protocol.CodeInvalidArgument)
	}
	return response, nil
}

func validateEnvelopeFields(fields map[string]json.RawMessage, required, allowed []string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		allowedSet[field] = struct{}{}
	}
	for field := range fields {
		if _, ok := allowedSet[field]; !ok {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return newProtocolError(protocol.CodeInvalidArgument)
		}
	}
	return nil
}

func decodeRPCParam(request rpcRequest, destination any) error {
	if destination == nil || len(request.Params) != 1 {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Params[0]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := protocol.Decode(request.Params[0], destination); err != nil {
		return err
	}
	return nil
}

func decodeRPCResult(response rpcResponse, destination any) error {
	if response.Error != nil {
		return response.Error.protocolError()
	}
	if destination == nil || len(response.Result) == 0 {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return protocol.Decode(response.Result, destination)
}

func validateEnvelope(data []byte, maximumBytes uint64) error {
	if err := validateMaximumBytes(maximumBytes); err != nil {
		return err
	}
	if len(data) == 0 {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if uint64(len(data)) > maximumBytes {
		return newProtocolError(protocol.CodeMessageTooLarge)
	}
	if bytes.IndexByte(data, '\n') >= 0 || bytes.IndexByte(data, '\r') >= 0 {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return nil
}

func validateMaximumBytes(maximumBytes uint64) error {
	if maximumBytes == 0 || maximumBytes > protocol.MaxMessageBytes {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return nil
}

type outboundValidatable interface {
	Validate() error
}

func validateOutbound(value any) error {
	if value == nil {
		return fmt.Errorf("outbound value is nil")
	}
	if validatable, ok := value.(outboundValidatable); ok {
		return validatable.Validate()
	}
	return nil
}

func mustMarshalParameter(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return data
}

func rpcErrorFrom(err error) *rpcError {
	value := normalizeProtocolError(err)
	code := rpcCodeServerError
	switch value.Code {
	case protocol.CodeInvalidArgument, protocol.CodeMessageTooLarge:
		code = rpcCodeInvalidParams
	case protocol.CodeNotSupported:
		code = rpcCodeMethodNotFound
	}
	return &rpcError{Code: code, Message: value.Message, Data: *value}
}

func normalizeProtocolError(err error) *protocol.Error {
	var structured *protocol.Error
	if errors.As(err, &structured) {
		if structured.Validate() == nil {
			if structured.Code == protocol.CodeNotSupported && len(structured.AdvertisedCapabilities) == 0 {
				return newProtocolError(protocol.CodeInvalidArgument)
			}
			value := *structured
			value.AdvertisedCapabilities = append([]protocol.CapabilityName(nil), structured.AdvertisedCapabilities...)
			return &value
		}
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	return newProtocolError(errorCode(err))
}

func errorCode(err error) protocol.ErrorCode {
	var structured *protocol.Error
	if errors.As(err, &structured) && structured.Validate() == nil {
		return structured.Code
	}
	switch {
	case errors.Is(err, context.Canceled):
		return protocol.CodeCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.CodeDeadlineExceeded
	default:
		return protocol.CodeUnavailable
	}
}

// newProtocolError constructs the closed, content-free protocol errors used by
// the SDK. CodeNotSupported callers must fill capability details or use
// protocol.NotSupported before sending the value.
func newProtocolError(code protocol.ErrorCode) *protocol.Error {
	if code == protocol.CodeNotSupported {
		// not_supported requires capability details; callers must use
		// protocol.NotSupported or the package helper instead.
		code = protocol.CodeInvalidArgument
	}
	message := canonicalProtocolMessage(code)
	if message == "" {
		code = protocol.CodeInvalidArgument
		message = canonicalProtocolMessage(code)
	}
	return &protocol.Error{Code: code, Message: message}
}

func canonicalProtocolMessage(code protocol.ErrorCode) string {
	switch code {
	case protocol.CodeInvalidArgument:
		return "protocol value is invalid"
	case protocol.CodeMessageTooLarge:
		return "protocol message exceeds its limit"
	case protocol.CodeNotSupported:
		return "required capability is not supported"
	case protocol.CodeSequenceConflict:
		return "event sequence conflicts with prior content"
	case protocol.CodeReplay:
		return "one-use value was already consumed"
	case protocol.CodeExpired:
		return "authorization or evidence has expired"
	case protocol.CodeUnauthenticated:
		return "protocol identity or signature is not authenticated"
	case protocol.CodePermissionDenied:
		return "operation is not authorized"
	case protocol.CodeConflict:
		return "operation conflicts with current state"
	case protocol.CodeDeadlineExceeded:
		return "operation deadline was exceeded"
	case protocol.CodeCancelled:
		return "operation was cancelled"
	case protocol.CodeResourceExhausted:
		return "protocol resource limit was exhausted"
	case protocol.CodeUnavailable:
		return "provider is unavailable"
	case protocol.CodeOutcomeUnknown:
		return "operation outcome is unknown"
	default:
		return ""
	}
}

func readFrame(reader *bufio.Reader, maximumBytes uint64) ([]byte, error) {
	if reader == nil {
		return nil, newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateMaximumBytes(maximumBytes); err != nil {
		return nil, err
	}

	var frame []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		terminated := err == nil
		payload := fragment
		if terminated {
			payload = fragment[:len(fragment)-1]
		}
		if uint64(len(frame))+uint64(len(payload)) > maximumBytes {
			return nil, newProtocolError(protocol.CodeMessageTooLarge)
		}
		frame = append(frame, payload...)

		switch {
		case terminated:
			if len(frame) == 0 || bytes.IndexByte(frame, '\r') >= 0 {
				return nil, newProtocolError(protocol.CodeInvalidArgument)
			}
			return frame, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(frame) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, newProtocolError(protocol.CodeInvalidArgument)
		default:
			return nil, err
		}
	}
}

func writeFrame(writer io.Writer, data []byte, maximumBytes uint64) error {
	if writer == nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}
	if err := validateEnvelope(data, maximumBytes); err != nil {
		return err
	}
	if err := validateObject(data); err != nil {
		return newProtocolError(protocol.CodeInvalidArgument)
	}

	frame := make([]byte, len(data)+1)
	copy(frame, data)
	frame[len(data)] = '\n'
	for len(frame) > 0 {
		written, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(frame) {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

type frameWriter struct {
	mu           sync.Mutex
	writer       io.Writer
	maximumBytes uint64
}

func newFrameWriter(writer io.Writer, maximumBytes uint64) *frameWriter {
	return &frameWriter{writer: writer, maximumBytes: maximumBytes}
}

func (w *frameWriter) write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFrame(w.writer, data, w.maximumBytes)
}

func (w *frameWriter) writeWithMaximum(data []byte, maximumBytes uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return writeFrame(w.writer, data, maximumBytes)
}
