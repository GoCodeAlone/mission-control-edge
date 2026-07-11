package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	idPattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	tokenPattern          = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	extensionPattern      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,63}$`)
	localSchemaRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
)

var providerCanonicalAuthorityKeys = map[string]struct{}{
	"tenant_id": {}, "project_id": {}, "initiative_id": {}, "work_item_id": {},
	"gateway_id": {}, "session_id": {}, "canonical_session_id": {},
	"correlation_id": {}, "causation_id": {}, "sensitivity": {}, "authority": {},
	"verification_tier": {}, "tier": {}, "verified": {},
}

var providerReviewAuthorityKeys = map[string]struct{}{
	"artifact_id": {}, "creator_type": {}, "creator_id": {}, "review_state": {},
	"classification": {}, "approval_id": {}, "approved": {}, "decision_revision": {},
}

type validatable interface{ Validate() error }

// Decode rejects ambiguous JSON and authority fields before decoding and validating dst.
func Decode(data []byte, dst any) error {
	if len(data) > MaxMessageBytes {
		return protocolError(CodeMessageTooLarge, "protocol message exceeds the hard limit")
	}
	if dst == nil {
		return protocolError(CodeInvalidArgument, "decode destination is required")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return protocolError(CodeInvalidArgument, "protocol message contains invalid or ambiguous JSON")
	}
	if err := rejectReservedAuthorityFields(data, dst); err != nil {
		return err
	}
	if err := decodeJSON(data, dst, isClosedSecurityDocument(dst)); err != nil {
		return protocolError(CodeInvalidArgument, "protocol message is invalid JSON")
	}
	if err := normalizeDecoded(dst); err != nil {
		return protocolError(CodeInvalidArgument, "protocol message contains invalid embedded JSON")
	}
	if value, ok := dst.(validatable); ok {
		if err := value.Validate(); err != nil {
			return protocolError(CodeInvalidArgument, err.Error())
		}
	}
	return nil
}

func isClosedSecurityDocument(dst any) bool {
	switch dst.(type) {
	case *Command, *ApprovalBinding, *ApprovalDecision, *IsolationEvidence, *ContentCustodyEvidence,
		*LiveVerificationAuthorization, *LiveVerificationReceipt, *VerificationEvidence, *Error:
		return true
	default:
		return false
	}
}

func decodeJSON(data []byte, dst any, strict bool) error {
	if !strict {
		return json.Unmarshal(data, dst)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func normalizeDecoded(dst any) error {
	switch value := dst.(type) {
	case *ProviderManifest:
		return compactExtensions(value.Extensions)
	case *Session:
		return compactExtensions(value.Extensions)
	case *ProviderEvent:
		payload, err := compactRaw(value.Payload)
		if err != nil {
			return err
		}
		value.Payload = payload
		return compactExtensions(value.Extensions)
	case *CanonicalEvent:
		payload, err := compactRaw(value.ProviderEvent.Payload)
		if err != nil {
			return err
		}
		value.ProviderEvent.Payload = payload
		return compactExtensions(value.ProviderEvent.Extensions)
	case *Command:
		payload, err := compactRaw(value.Payload)
		if err != nil {
			return err
		}
		value.Payload = payload
		return nil
	case *CommandResult:
		if len(value.Result) == 0 {
			return nil
		}
		result, err := compactRaw(value.Result)
		if err != nil {
			return err
		}
		value.Result = result
		return nil
	case *Artifact:
		return compactExtensions(value.Extensions)
	case *ProviderArtifactReport:
		return compactExtensions(value.Extensions)
	case *Environment:
		if len(value.Configuration) == 0 {
			return nil
		}
		configuration, err := compactRaw(value.Configuration)
		if err != nil {
			return err
		}
		value.Configuration = configuration
	case *EnvironmentProvisionRequest:
		configuration, err := compactRaw(value.Configuration)
		if err != nil {
			return err
		}
		value.Configuration = configuration
	case *RuntimeCreateSessionRequest:
		configuration, err := compactRaw(value.Configuration)
		if err != nil {
			return err
		}
		value.Configuration = configuration
	case *WorkspaceCreateRequest:
		configuration, err := compactRaw(value.Configuration)
		if err != nil {
			return err
		}
		value.Configuration = configuration
	case *HarnessLaunchRequest:
		configuration, err := compactRaw(value.Configuration)
		if err != nil {
			return err
		}
		value.Configuration = configuration
	case *AgentMessageRequest:
		message, err := compactRaw(value.Message)
		if err != nil {
			return err
		}
		value.Message = message
	case *ContextDeliverRequest:
		content, err := compactRaw(value.Content)
		if err != nil {
			return err
		}
		value.Content = content
	case *AgentTool:
		inputSchema, err := compactRaw(value.InputSchema)
		if err != nil {
			return err
		}
		value.InputSchema = inputSchema
	}
	return nil
}

func compactRaw(value json.RawMessage) (json.RawMessage, error) {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, value); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), buffer.Bytes()...), nil
}

func compactExtensions(values map[string]json.RawMessage) error {
	for key, value := range values {
		compact, err := compactRaw(value)
		if err != nil {
			return err
		}
		values[key] = compact
	}
	return nil
}

func rejectReservedExtensions(values map[string]json.RawMessage) error {
	for _, value := range values {
		if err := rejectReservedProviderContent(value, nil); err != nil {
			return err
		}
	}
	return nil
}

func rejectReservedProviderContent(data []byte, allowedRoot map[string]struct{}) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return protocolError(CodeInvalidArgument, "provider content contains ambiguous JSON")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return protocolError(CodeInvalidArgument, "provider content is invalid JSON")
	}
	type node struct {
		value any
		root  bool
	}
	stack := []node{{value: value, root: true}}
	for len(stack) > 0 {
		last := len(stack) - 1
		current := stack[last]
		stack = stack[:last]
		switch typed := current.value.(type) {
		case map[string]any:
			for key, child := range typed {
				_, allowed := allowedRoot[key]
				if !current.root || !allowed {
					if _, reserved := providerCanonicalAuthorityKeys[key]; reserved {
						return protocolError(CodePermissionDenied, "provider content supplied canonical authority")
					}
					if _, reserved := providerReviewAuthorityKeys[key]; reserved {
						return protocolError(CodePermissionDenied, "provider content supplied review authority")
					}
				}
				stack = append(stack, node{value: child})
			}
		case []any:
			for _, child := range typed {
				stack = append(stack, node{value: child})
			}
		}
	}
	return nil
}

func rejectReservedAuthorityFields(data []byte, dst any) error {
	switch dst.(type) {
	case *ProviderManifest, *ProviderEvent, *ProviderArtifactReport:
		return rejectReservedProviderObject(data, dst)
	case *CanonicalEvent:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil {
			return protocolError(CodeInvalidArgument, "protocol message must be an object")
		}
		nested, exists := object["provider_event"]
		if !exists {
			return nil
		}
		return rejectReservedProviderObject(nested, new(ProviderEvent))
	default:
		return nil
	}
}

func rejectReservedProviderObject(data []byte, dst any) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return protocolError(CodeInvalidArgument, "protocol message must be an object")
	}
	for key := range providerCanonicalAuthorityKeys {
		if _, exists := object[key]; exists {
			return protocolError(CodePermissionDenied, "provider supplied a gateway-owned authority field")
		}
	}
	if _, providerArtifact := dst.(*ProviderArtifactReport); providerArtifact {
		for key := range providerReviewAuthorityKeys {
			if _, exists := object[key]; exists {
				return protocolError(CodePermissionDenied, "provider supplied artifact review authority")
			}
		}
	}
	if _, providerEvent := dst.(*ProviderEvent); providerEvent {
		allowedPayloadKeys := map[string]struct{}(nil)
		var eventType string
		if rawType, exists := object["type"]; exists && json.Unmarshal(rawType, &eventType) == nil && eventType == "session.state_changed" {
			allowedPayloadKeys = map[string]struct{}{"authority": {}}
		}
		if payload, exists := object["payload"]; exists {
			if err := rejectReservedProviderContent(payload, allowedPayloadKeys); err != nil {
				return err
			}
		}
	}
	if rawExtensions, exists := object["extensions"]; exists {
		var extensions map[string]json.RawMessage
		if err := json.Unmarshal(rawExtensions, &extensions); err != nil {
			return protocolError(CodeInvalidArgument, "provider extensions are invalid")
		}
		if err := rejectReservedExtensions(extensions); err != nil {
			return err
		}
	}
	return nil
}

func validateCompactJSONDigest(field string, value json.RawMessage, expected Digest) error {
	if len(value) == 0 {
		return fmt.Errorf("%s is required", field)
	}
	if err := rejectDuplicateKeys(value); err != nil {
		return fmt.Errorf("%s contains ambiguous JSON", field)
	}
	compact, err := compactRaw(value)
	if err != nil {
		return fmt.Errorf("%s is invalid JSON", field)
	}
	if err := expected.Validate(); err != nil {
		return err
	}
	sum := sha256.Sum256(compact)
	actual := Digest("sha256:" + hex.EncodeToString(sum[:]))
	if actual != expected {
		return fmt.Errorf("%s digest does not match compact JSON", field)
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var consume func() error
	consume = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := consume(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := consume(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter")
		}
	}
	if err := consume(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateProtocol(version string) error {
	if version != ProtocolVersion {
		return fmt.Errorf("protocol_version must be %s", ProtocolVersion)
	}
	return nil
}

func validateID(field, value string) error {
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateToken(field, value string) error {
	if !tokenPattern.MatchString(value) {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateVersion(field, value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t ") {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateText(field, value string, max int) error {
	return validateTextRange(field, value, 1, max)
}

func validateTextRange(field, value string, minimum, maximum int) error {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%s is invalid", field)
	}
	return nil
}

func validateExecutable(value string) error {
	if err := validateText("executable", value, 256); err != nil {
		return err
	}
	if strings.ContainsAny(value, "/\\") || value == "." || value == ".." {
		return fmt.Errorf("executable must be a name, not a path")
	}
	return nil
}

func validateLocalSchemaRef(value string) error {
	if len(value) > 512 || !localSchemaRefPattern.MatchString(value) || strings.Contains(value, "..") {
		return fmt.Errorf("configuration_schema is invalid")
	}
	return nil
}

func validateExtensions(values map[string]json.RawMessage) error {
	if len(values) > 64 {
		return fmt.Errorf("too many extensions")
	}
	total := 0
	for key, value := range values {
		if !extensionPattern.MatchString(key) {
			return fmt.Errorf("extension key is invalid")
		}
		if !json.Valid(value) {
			return fmt.Errorf("extension value is invalid JSON")
		}
		total += len(key) + len(value)
	}
	if total > 256<<10 {
		return fmt.Errorf("extensions exceed size limit")
	}
	return nil
}

func validateTime(field string, value time.Time) error {
	if value.IsZero() || value.Location() != time.UTC {
		return fmt.Errorf("%s must be a UTC timestamp", field)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func validateUniqueStrings(field string, values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s contains an invalid value", field)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("%s contains a duplicate", field)
		}
		seen[value] = struct{}{}
	}
	return nil
}
