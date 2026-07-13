// Command mc-schema generates the checked-in provider protocol schemas.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const (
	schemaVersion  = "https://json-schema.org/draft/2020-12/schema"
	openRPCVersion = "1.4.1"
)

func main() {
	output := flag.String("output", "schema", "directory for generated schema documents")
	flag.Parse()

	documents := map[string]any{
		"provider-manifest.v1alpha1.schema.json": providerManifestSchema(),
		"session.v1alpha1.schema.json":           sessionSchema(),
		"event.v1alpha1.schema.json":             eventSchema(),
		"command.v1alpha1.schema.json":           commandSchema(),
		"openrpc.v1alpha1.json":                  openRPCDocument(),
	}
	// Generated schemas are public source artifacts and must be traversable/readable.
	if err := os.MkdirAll(*output, 0o755); err != nil { //nolint:gosec
		fatal(err)
	}
	names := make([]string, 0, len(documents))
	for name := range documents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := json.MarshalIndent(documents[name], "", "  ")
		if err != nil {
			fatal(fmt.Errorf("encode %s: %w", name, err))
		}
		data = append(data, '\n')
		// Generated schemas are checked-in public source artifacts, not sensitive state.
		if err := os.WriteFile(filepath.Join(*output, name), data, 0o644); err != nil { //nolint:gosec
			fatal(fmt.Errorf("write %s: %w", name, err))
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func providerManifestSchema() map[string]any {
	return objectSchema(
		"urn:gocodealone:mission-control:provider-manifest:v1alpha1",
		"Mission Control provider manifest v1alpha1",
		[]string{"protocol_version", "id", "roles", "name", "version", "executable", "platforms", "capabilities", "interaction_modes", "permissions", "configuration_schema", "extensions"},
		map[string]any{
			"protocol_version":     constant(protocol.ProtocolVersion),
			"id":                   idString(),
			"roles":                array(enum("agent-harness", "session-runtime", "execution-environment", "orchestration"), 1, 4, true),
			"name":                 boundedString(1, 256),
			"version":              versionString(),
			"executable":           executableString(),
			"platforms":            array(ref("#/$defs/platform"), 1, 32, true),
			"capabilities":         array(ref("#/$defs/capability"), 1, 256, true),
			"interaction_modes":    array(tokenString(1, 128), 1, 32, true),
			"permissions":          array(tokenString(1, 128), 0, 64, true),
			"configuration_schema": localSchemaReference(),
			"extensions":           providerExtensionsSchema("#/$defs/provider_local_value"),
		},
		map[string]any{
			"platform":             platformDefinition(),
			"capability":           capabilityDefinition(),
			"provider_local_value": providerLocalValueDefinition("#/$defs/provider_local_value"),
		},
		providerAuthorityExclusion(),
	)
}

func sessionSchema() map[string]any {
	return objectSchema(
		"urn:gocodealone:mission-control:session:v1alpha1",
		"Mission Control canonical session v1alpha1",
		[]string{"protocol_version", "session_id", "gateway_id", "environment", "harness", "lifecycle", "activity", "health", "context_version", "extensions"},
		map[string]any{
			"protocol_version": constant(protocol.ProtocolVersion),
			"session_id":       idString(),
			"gateway_id":       idString(),
			"environment":      ref("#/$defs/provider_binding"),
			"runtime":          ref("#/$defs/provider_binding"),
			"harness":          ref("#/$defs/provider_binding"),
			"lifecycle":        stateReportDefinition("lifecycle", []string{"provisioning", "starting", "running", "stopped", "terminated", "archived", "disconnected", "unknown"}),
			"activity":         stateReportDefinition("activity", []string{"idle", "working", "waiting_for_user", "waiting_for_approval", "blocked", "done", "failed", "unknown"}),
			"health":           stateReportDefinition("health", []string{"healthy", "degraded", "unreachable", "unknown"}),
			"context_version":  idString(),
			"extensions":       extensionsSchema(),
		},
		map[string]any{
			"provider_binding": providerBindingDefinition(),
			"context_receipt":  contextReceiptDefinition(),
			"artifact":         artifactDefinition(),
		},
	)
}

func eventSchema() map[string]any {
	providerEvent := closedObject(
		[]string{"protocol_version", "event_id", "provider_id", "role", "stream_id", "type", "sequence", "observed_at", "payload", "extensions"},
		map[string]any{
			"protocol_version":  constant(protocol.ProtocolVersion),
			"event_id":          idString(),
			"provider_id":       idString(),
			"role":              enum("provider", "agent-harness", "session-runtime", "execution-environment", "orchestration"),
			"stream_id":         idString(),
			"native_session_id": nativeIDString(),
			"type":              providerEventTypeString(),
			"sequence":          integer(1),
			"observed_at":       timestamp(),
			"payload":           map[string]any{},
			"extensions":        providerExtensionsSchema("#/$defs/provider_local_value"),
		},
	)
	providerEvent["additionalProperties"] = true
	providerEvent["allOf"] = []any{
		providerAuthorityExclusion(),
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"type": map[string]any{"pattern": `^session\.`}},
				"required":   []string{"type"},
			},
			"then": map[string]any{
				"required": []string{"native_session_id"},
				"properties": map[string]any{
					"role": map[string]any{"not": constant("provider")},
				},
			},
		},
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"type": constant("session.state_changed")},
				"required":   []string{"type"},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"payload": map[string]any{"oneOf": []any{
						ref("#/$defs/lifecycle_state"),
						ref("#/$defs/activity_state"),
						ref("#/$defs/health_state"),
					}},
				},
			},
			"else": map[string]any{
				"properties": map[string]any{"payload": ref("#/$defs/provider_local_value")},
			},
		},
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"type": map[string]any{"pattern": `^artifact\.`}},
				"required":   []string{"type"},
			},
			"then": map[string]any{
				"properties": map[string]any{"payload": ref("#/$defs/provider_artifact_report")},
			},
		},
	}
	canonicalEvent := closedObject(
		[]string{"protocol_version", "tenant_id", "gateway_id", "correlation_id", "sensitivity", "authority", "provider_event"},
		map[string]any{
			"protocol_version": constant(protocol.ProtocolVersion),
			"tenant_id":        idString(),
			"gateway_id":       idString(),
			"session_id":       idString(),
			"correlation_id":   idString(),
			"causation_id":     idString(),
			"sensitivity":      enum("public", "metadata", "internal", "confidential", "restricted"),
			"authority":        constant("gateway-assigned"),
			"provider_event":   ref("#/$defs/provider_event"),
		},
	)
	canonicalEvent["additionalProperties"] = true
	canonicalEvent["allOf"] = []any{
		map[string]any{
			"if": map[string]any{
				"properties": map[string]any{
					"provider_event": map[string]any{
						"anyOf": []any{
							map[string]any{"properties": map[string]any{"type": map[string]any{"pattern": `^session\.`}}, "required": []string{"type"}},
							map[string]any{"required": []string{"native_session_id"}},
						},
					},
				},
			},
			"then": map[string]any{"required": []string{"session_id"}},
		},
	}
	return map[string]any{
		"$schema": schemaVersion,
		"$id":     "urn:gocodealone:mission-control:event:v1alpha1",
		"title":   "Mission Control provider and canonical events v1alpha1",
		"oneOf": []any{
			ref("#/$defs/provider_event"),
			ref("#/$defs/canonical_event"),
		},
		"$defs": map[string]any{
			"provider_event":           providerEvent,
			"canonical_event":          canonicalEvent,
			"provider_artifact_report": providerArtifactReportDefinition("#/$defs/provider_local_value"),
			"provider_local_value":     providerLocalValueDefinition("#/$defs/provider_local_value"),
			"lifecycle_state":          stateReportDefinition("lifecycle", []string{"provisioning", "starting", "running", "stopped", "terminated", "archived", "disconnected", "unknown"}),
			"activity_state":           stateReportDefinition("activity", []string{"idle", "working", "waiting_for_user", "waiting_for_approval", "blocked", "done", "failed", "unknown"}),
			"health_state":             stateReportDefinition("health", []string{"healthy", "degraded", "unreachable", "unknown"}),
			"approval_decision":        approvalDecisionDefinition(),
			"verification":             verificationDefinition(),
		},
	}
}

func commandSchema() map[string]any {
	document := objectSchema(
		"urn:gocodealone:mission-control:command:v1alpha1",
		"Mission Control command v1alpha1",
		[]string{"protocol_version", "command_id", "capability", "idempotency_key", "cancellation_token", "deadline", "delivery_class", "payload"},
		map[string]any{
			"protocol_version":   constant(protocol.ProtocolVersion),
			"command_id":         idString(),
			"session_id":         idString(),
			"capability":         boundedString(1, 128),
			"idempotency_key":    boundedString(16, 256),
			"cancellation_token": boundedString(16, 256),
			"deadline":           timestamp(),
			"delivery_class":     enum("provider_idempotent", "state_reconciled", "at_most_once"),
			"payload":            map[string]any{},
		},
		map[string]any{
			"approval_binding":   approvalBindingDefinition(),
			"isolation_evidence": evidenceDefinition("isolation"),
			"custody_evidence":   evidenceDefinition("custody"),
		},
	)
	document["additionalProperties"] = false
	variants := make([]any, 0, len(protocol.KnownCapabilities()))
	for _, capability := range protocol.KnownCapabilities() {
		if !capability.Mutating {
			continue
		}
		variant := map[string]any{"properties": map[string]any{
			"capability":     constant(string(capability.Name)),
			"delivery_class": constant(string(capability.DeliveryClass)),
		}}
		if schemaCommandRequiresSession(capability.Name) {
			variant["required"] = []string{"session_id"}
		}
		variants = append(variants, variant)
	}
	variants = append(variants, map[string]any{"properties": map[string]any{
		"capability": map[string]any{"type": "string", "pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,127}$`},
	}})
	document["allOf"] = []any{map[string]any{"oneOf": variants}}
	return document
}

func schemaCommandRequiresSession(capability protocol.CapabilityName) bool {
	value := string(capability)
	for _, prefix := range []string{"runtime.", "terminal.", "harness.", "agent.", "context.", "approval.", "artifact."} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func openRPCDocument() map[string]any {
	capabilities := protocol.KnownCapabilities()
	sort.Slice(capabilities, func(i, j int) bool { return capabilities[i].Name < capabilities[j].Name })
	methods := make([]any, 0, len(capabilities))
	for _, capability := range capabilities {
		requestSchema := openRPCRequestSchema(capability)
		method := map[string]any{
			"name":           capability.Name,
			"summary":        "Mission Control provider capability " + string(capability.Name),
			"paramStructure": "by-position",
			"tags": []any{
				map[string]any{"name": capability.Role},
			},
			"params": []any{
				map[string]any{"name": "request", "required": true, "schema": requestSchema},
			},
			"result": map[string]any{"name": "result", "schema": openRPCResultSchema(capability)},
			"errors": []any{ref("#/components/errors/not_supported")},
		}
		if capability.Mutating {
			method["x-delivery-class"] = capability.DeliveryClass
		}
		methods = append(methods, method)
	}
	return map[string]any{
		"openrpc": openRPCVersion,
		"info": map[string]any{
			"title":   "Mission Control Provider Protocol",
			"version": protocol.ProtocolVersion,
		},
		"methods": methods,
		"components": map[string]any{
			"errors": map[string]any{
				"not_supported": map[string]any{
					"code":    -32004,
					"message": "required capability is not supported",
					"data":    ref("#/components/schemas/ProtocolError"),
				},
			},
			"schemas": map[string]any{
				"Capability":         capabilityDefinition(),
				"ProtocolError":      protocolErrorDefinition(),
				"ProviderLocalValue": providerLocalValueDefinition("#/components/schemas/ProviderLocalValue"),
				"ProviderManifest":   ref("provider-manifest.v1alpha1.schema.json"),
				"Session":            ref("session.v1alpha1.schema.json"),
				"Event":              ref("event.v1alpha1.schema.json"),
				"Command":            ref("command.v1alpha1.schema.json"),
				"ContextReceipt":     contextReceiptDefinition(),
				"Artifact":           artifactDefinition(),
				"ApprovalDecision":   approvalDecisionDefinition(),
				"Verification":       verificationDefinition(),
				"IsolationEvidence":  evidenceDefinition("isolation"),
				"CustodyEvidence":    evidenceDefinition("custody"),
			},
		},
	}
}

func openRPCRequestSchema(capability protocol.CapabilityDescriptor) map[string]any {
	if capability.Mutating {
		return map[string]any{
			"allOf": []any{
				ref("command.v1alpha1.schema.json"),
				map[string]any{
					"type": "object",
					"properties": map[string]any{
						"capability": constant(string(capability.Name)),
						"payload":    methodPayloadSchema(capability.Name),
					},
				},
			},
		}
	}
	switch capability.Name {
	case "provider.initialize":
		return providerInitializeRequestDefinition()
	case "provider.health", "provider.capabilities", "runtime.list_sessions", "workspace.list", "harness.list":
		return emptyObject()
	case "events.subscribe":
		return eventSubscribeRequestDefinition()
	case "command.get_result":
		return commandResultRequestDefinition()
	case "environment.inspect", "environment.health":
		return environmentInspectRequestDefinition()
	case "runtime.get_session", "runtime.snapshot":
		return runtimeSessionRequestDefinition()
	case "terminal.read":
		return terminalReadRequestDefinition()
	case "terminal.subscribe":
		return terminalSubscribeRequestDefinition()
	case "workspace.get", "topology.get", "topology.subscribe", "pane.list":
		return workspaceRequestDefinition()
	case "pane.get":
		return paneRequestDefinition()
	case "harness.inspect", "agent.get_state", "agent.get_usage", "agent.get_pending_approvals", "agent.get_tools", "agent.get_native_identity":
		return harnessSessionRequestDefinition()
	case "context.confirm":
		return contextConfirmRequestDefinition()
	case "approval.list":
		return approvalListRequestDefinition()
	case "artifact.list":
		return artifactListRequestDefinition()
	default:
		panic(fmt.Sprintf("OpenRPC request schema missing for %s", capability.Name))
	}
}

func methodPayloadSchema(name protocol.CapabilityName) map[string]any {
	switch name {
	case "provider.shutdown":
		return emptyObject()
	case "events.unsubscribe":
		return eventUnsubscribeRequestDefinition()
	case "environment.provision":
		return environmentProvisionRequestDefinition()
	case "environment.mount":
		return environmentMountRequestDefinition()
	case "environment.shutdown":
		return environmentInspectRequestDefinition()
	case "runtime.create_session":
		return runtimeCreateSessionRequestDefinition()
	case "runtime.stop_session", "runtime.terminate_session", "runtime.attach", "runtime.detach", "runtime.checkpoint", "runtime.adopt", "runtime.resume", "runtime.clone", "runtime.fork", "runtime.export", "runtime.archive":
		return runtimeSessionRequestDefinition()
	case "runtime.restore", "runtime.import":
		return runtimeRestoreRequestDefinition()
	case "runtime.migrate":
		return runtimeTransferRequestDefinition()
	case "terminal.send_input":
		return terminalInputRequestDefinition()
	case "terminal.send_keys":
		return terminalKeysRequestDefinition()
	case "terminal.resize":
		return terminalResizeRequestDefinition()
	case "terminal.attach":
		return terminalSubscribeRequestDefinition()
	case "terminal.detach":
		return terminalDetachRequestDefinition()
	case "workspace.create":
		return workspaceCreateRequestDefinition()
	case "workspace.close":
		return workspaceRequestDefinition()
	case "pane.create":
		return paneCreateRequestDefinition()
	case "pane.split":
		return paneSplitRequestDefinition()
	case "pane.focus", "pane.close":
		return paneRequestDefinition()
	case "pane.resize":
		return paneResizeRequestDefinition()
	case "harness.launch":
		return harnessLaunchRequestDefinition()
	case "harness.resume":
		return harnessResumeRequestDefinition()
	case "harness.stop", "agent.interrupt", "agent.cancel":
		return harnessSessionRequestDefinition()
	case "agent.send_message":
		return agentMessageRequestDefinition()
	case "context.deliver":
		return contextDeliverRequestDefinition()
	case "approval.approve", "approval.reject", "approval.expire":
		return approvalActionRequestDefinition(name)
	case "artifact.register":
		return closedObject([]string{"artifact"}, map[string]any{"artifact": providerArtifactReportDefinition("#/components/schemas/ProviderLocalValue")})
	default:
		panic(fmt.Sprintf("OpenRPC command payload schema missing for %s", name))
	}
}

func openRPCResultSchema(capability protocol.CapabilityDescriptor) map[string]any {
	switch capability.Name {
	case "provider.initialize":
		return providerInitializeResultDefinition()
	case "provider.capabilities":
		return closedObject([]string{"provider_id", "roles", "capabilities"}, map[string]any{
			"provider_id":  idString(),
			"roles":        array(enum("agent-harness", "session-runtime", "execution-environment", "orchestration"), 1, 4, true),
			"capabilities": array(ref("#/components/schemas/Capability"), 1, 256, true),
		})
	case "provider.health":
		return closedObject([]string{"provider_id", "health"}, map[string]any{
			"provider_id": idString(),
			"health":      stateReportDefinition("health", []string{"healthy", "degraded", "unreachable", "unknown"}),
		})
	case "provider.shutdown", "events.unsubscribe", "workspace.close", "pane.close", "harness.stop", "agent.interrupt", "agent.cancel":
		return operationResultDefinition()
	case "agent.send_message":
		return agentStateResultDefinition()
	case "approval.approve", "approval.reject", "approval.expire":
		return closedObject([]string{"operation"}, map[string]any{"operation": operationResultDefinition()})
	case "artifact.register":
		return closedObject([]string{"operation"}, map[string]any{"operation": operationResultDefinition()})
	case "events.subscribe", "topology.subscribe":
		return eventSubscriptionDefinition()
	case "command.get_result":
		return commandResultDefinition()
	case "environment.inspect", "environment.provision", "environment.mount", "environment.health", "environment.shutdown":
		return environmentResultDefinition()
	case "runtime.list_sessions":
		return runtimeListSessionsResultDefinition()
	case "runtime.get_session", "runtime.create_session", "runtime.stop_session", "runtime.terminate_session", "runtime.attach", "runtime.detach", "runtime.restore", "runtime.adopt", "runtime.resume", "runtime.clone", "runtime.fork", "runtime.migrate", "runtime.import", "runtime.archive":
		return runtimeSessionResultDefinition()
	case "runtime.snapshot", "runtime.checkpoint", "runtime.export":
		return runtimeSnapshotDefinition()
	case "terminal.read":
		return terminalChunkDefinition()
	case "terminal.subscribe", "terminal.attach":
		return eventSubscriptionDefinition()
	case "terminal.send_input", "terminal.send_keys", "terminal.resize", "terminal.detach":
		return terminalAckDefinition()
	case "workspace.list":
		return workspaceListResultDefinition()
	case "workspace.get", "workspace.create":
		return workspaceDefinition()
	case "topology.get":
		return topologySnapshotDefinition()
	case "pane.list":
		return paneListResultDefinition()
	case "pane.get", "pane.create", "pane.split", "pane.focus", "pane.resize":
		return paneDefinition()
	case "harness.list":
		return harnessListResultDefinition()
	case "harness.inspect", "harness.launch", "harness.resume":
		return harnessSessionResultDefinition()
	case "agent.get_state":
		return agentStateResultDefinition()
	case "agent.get_usage":
		return closedObject([]string{"usage"}, map[string]any{"usage": usageDefinition()})
	case "agent.get_pending_approvals", "approval.list":
		return approvalListResultDefinition()
	case "agent.get_tools":
		return agentToolsResultDefinition()
	case "agent.get_native_identity":
		return agentNativeIdentityResultDefinition()
	case "context.deliver", "context.confirm":
		return closedObject([]string{"receipt"}, map[string]any{"receipt": contextReceiptDefinition()})
	case "artifact.list":
		return artifactListResultDefinition()
	default:
		panic(fmt.Sprintf("OpenRPC result schema missing for %s", capability.Name))
	}
}

func emptyObject() map[string]any { return closedObject(nil, map[string]any{}) }

func protocolErrorDefinition() map[string]any {
	value := closedObject([]string{"code", "message"}, map[string]any{
		"code":                    enum("invalid_argument", "message_too_large", "not_supported", "sequence_conflict", "replay", "expired", "unauthenticated", "permission_denied", "conflict", "deadline_exceeded", "cancelled", "resource_exhausted", "unavailable", "outcome_unknown"),
		"message":                 enum("protocol value is invalid", "protocol message exceeds its limit", "required capability is not supported", "event sequence conflicts with prior content", "one-use value was already consumed", "authorization or evidence has expired", "protocol identity or signature is not authenticated", "operation is not authorized", "operation conflicts with current state", "operation deadline was exceeded", "operation was cancelled", "protocol resource limit was exhausted", "provider is unavailable", "operation outcome is unknown"),
		"required_capability":     capabilityNameString(),
		"advertised_capabilities": array(capabilityNameString(), 0, 256, true),
	})
	pairs := [][2]string{
		{"invalid_argument", "protocol value is invalid"},
		{"message_too_large", "protocol message exceeds its limit"},
		{"not_supported", "required capability is not supported"},
		{"sequence_conflict", "event sequence conflicts with prior content"},
		{"replay", "one-use value was already consumed"},
		{"expired", "authorization or evidence has expired"},
		{"unauthenticated", "protocol identity or signature is not authenticated"},
		{"permission_denied", "operation is not authorized"},
		{"conflict", "operation conflicts with current state"},
		{"deadline_exceeded", "operation deadline was exceeded"},
		{"cancelled", "operation was cancelled"},
		{"resource_exhausted", "protocol resource limit was exhausted"},
		{"unavailable", "provider is unavailable"},
		{"outcome_unknown", "operation outcome is unknown"},
	}
	variants := make([]any, 0, len(pairs))
	for _, pair := range pairs {
		variants = append(variants, map[string]any{"properties": map[string]any{"code": constant(pair[0]), "message": constant(pair[1])}})
	}
	value["allOf"] = []any{
		map[string]any{"oneOf": variants},
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"code": constant("not_supported")}, "required": []string{"code"}},
			"then": map[string]any{"required": []string{"required_capability", "advertised_capabilities"}},
			"else": map[string]any{"not": map[string]any{"anyOf": []any{map[string]any{"required": []string{"required_capability"}}, map[string]any{"required": []string{"advertised_capabilities"}}}}},
		},
	}
	return value
}

func operationResultDefinition() map[string]any {
	value := closedObject([]string{"operation_id", "status", "observed_at"}, map[string]any{
		"operation_id":     nativeIDString(),
		"status":           enum("accepted", "running", "succeeded", "failed", "outcome_unknown"),
		"observed_at":      timestamp(),
		"result_reference": opaqueReference(),
		"error":            protocolErrorDefinition(),
	})
	value["allOf"] = []any{
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"status": constant("failed")}, "required": []string{"status"}},
			"then": map[string]any{"required": []string{"error"}},
			"else": map[string]any{"not": map[string]any{"required": []string{"error"}}},
		},
	}
	return value
}

func providerInitializeRequestDefinition() map[string]any {
	return closedObject([]string{"supported_protocol_versions", "gateway_version", "platform", "required_capabilities", "maximum_message_bytes", "maximum_chunk_bytes", "replay_supported", "authentication_modes", "experimental_features"}, map[string]any{
		"supported_protocol_versions": array(versionString(), 1, 8, true),
		"gateway_version":             versionString(),
		"platform":                    platformDefinition(),
		"required_capabilities":       array(capabilityNameString(), 0, 256, true),
		"maximum_message_bytes":       boundedInteger(1, protocol.MaxMessageBytes),
		"maximum_chunk_bytes":         boundedInteger(1, protocol.MaxTerminalChunkBytes),
		"replay_supported":            map[string]any{"type": "boolean"},
		"authentication_modes":        array(tokenString(1, 128), 1, 16, true),
		"experimental_features":       array(tokenString(1, 128), 0, 64, true),
	})
}

func providerInitializeResultDefinition() map[string]any {
	return closedObject([]string{"protocol_version", "manifest", "maximum_message_bytes", "maximum_chunk_bytes", "replay_supported", "authentication_mode", "experimental_features"}, map[string]any{
		"protocol_version":       constant(protocol.ProtocolVersion),
		"manifest":               ref("provider-manifest.v1alpha1.schema.json"),
		"native_runtime_version": versionString(),
		"maximum_message_bytes":  boundedInteger(1, protocol.MaxMessageBytes),
		"maximum_chunk_bytes":    boundedInteger(1, protocol.MaxTerminalChunkBytes),
		"replay_supported":       map[string]any{"type": "boolean"},
		"authentication_mode":    tokenString(1, 128),
		"experimental_features":  array(tokenString(1, 128), 0, 64, true),
	})
}

func eventSubscribeRequestDefinition() map[string]any {
	return closedObject([]string{"cursors", "event_types", "window_size"}, map[string]any{
		"cursors":     array(eventSubscriptionCursorDefinition(), 0, 4096, true),
		"event_types": array(providerEventTypeString(), 0, 256, true),
		"window_size": boundedInteger(1, 4096),
	})
}

func eventUnsubscribeRequestDefinition() map[string]any {
	return closedObject([]string{"subscription_id"}, map[string]any{"subscription_id": nativeIDString()})
}

func eventSubscriptionDefinition() map[string]any {
	return closedObject([]string{"subscription_id", "cursors"}, map[string]any{
		"subscription_id": nativeIDString(),
		"cursors":         array(eventSubscriptionCursorDefinition(), 0, 4096, true),
	})
}

func eventSubscriptionCursorDefinition() map[string]any {
	return closedObject([]string{"role", "stream_id", "after_sequence"}, map[string]any{
		"role":           enum("provider", "agent-harness", "session-runtime", "execution-environment", "orchestration"),
		"stream_id":      idString(),
		"after_sequence": integer(0),
	})
}

func commandResultRequestDefinition() map[string]any {
	return closedObject([]string{"command_id"}, map[string]any{"command_id": idString()})
}

func commandResultDefinition() map[string]any {
	value := closedObject([]string{"command_id", "status", "observed_at"}, map[string]any{
		"command_id":  idString(),
		"status":      enum("pending", "succeeded", "failed", "outcome_unknown"),
		"result":      map[string]any{},
		"error":       protocolErrorDefinition(),
		"observed_at": timestamp(),
	})
	value["allOf"] = []any{
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"status": constant("succeeded")}, "required": []string{"status"}},
			"then": map[string]any{"required": []string{"result"}, "not": map[string]any{"required": []string{"error"}}},
		},
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"status": constant("failed")}, "required": []string{"status"}},
			"then": map[string]any{"required": []string{"error"}, "not": map[string]any{"required": []string{"result"}}},
		},
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"status": enum("pending", "outcome_unknown")}, "required": []string{"status"}},
			"then": map[string]any{"not": map[string]any{"anyOf": []any{map[string]any{"required": []string{"result"}}, map[string]any{"required": []string{"error"}}}}},
		},
	}
	return value
}

func environmentInspectRequestDefinition() map[string]any {
	return closedObject([]string{"native_environment_id"}, map[string]any{"native_environment_id": nativeIDString()})
}

func environmentProvisionRequestDefinition() map[string]any {
	return closedObject([]string{"configuration", "configuration_digest"}, map[string]any{
		"configuration":        map[string]any{},
		"configuration_digest": digestSchema(),
		"image_digest":         digestSchema(),
	})
}

func environmentMountRequestDefinition() map[string]any {
	return closedObject([]string{"native_environment_id", "mount_id", "resource_reference", "read_only"}, map[string]any{
		"native_environment_id": nativeIDString(),
		"mount_id":              idString(),
		"resource_reference":    opaqueReference(),
		"read_only":             map[string]any{"type": "boolean"},
	})
}

func environmentDefinition() map[string]any {
	return closedObject([]string{"provider_id", "native_environment_id", "platform", "health"}, map[string]any{
		"provider_id":           idString(),
		"native_environment_id": nativeIDString(),
		"platform":              platformDefinition(),
		"health":                stateReportDefinition("health", []string{"healthy", "degraded", "unreachable", "unknown"}),
		"configuration":         map[string]any{},
	})
}

func environmentResultDefinition() map[string]any {
	return closedObject([]string{"environment"}, map[string]any{"environment": environmentDefinition()})
}

func runtimeSessionRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id"}, map[string]any{"native_session_id": nativeIDString()})
}

func runtimeRestoreRequestDefinition() map[string]any {
	return closedObject([]string{"snapshot_id", "native_environment_id"}, map[string]any{
		"snapshot_id":           nativeIDString(),
		"native_environment_id": nativeIDString(),
	})
}

func runtimeCreateSessionRequestDefinition() map[string]any {
	return closedObject([]string{"native_environment_id", "configuration", "configuration_digest"}, map[string]any{
		"native_environment_id": nativeIDString(),
		"name":                  boundedString(1, 128),
		"configuration":         map[string]any{},
		"configuration_digest":  digestSchema(),
	})
}

func runtimeTransferRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "native_environment_id"}, map[string]any{
		"native_session_id":     nativeIDString(),
		"native_environment_id": nativeIDString(),
		"checkpoint_reference":  nativeIDString(),
	})
}

func runtimeSessionDefinition() map[string]any {
	return closedObject([]string{"provider_id", "native_session_id", "lifecycle", "health", "extensions"}, map[string]any{
		"provider_id":       idString(),
		"native_session_id": nativeIDString(),
		"lifecycle":         stateReportDefinition("lifecycle", []string{"provisioning", "starting", "running", "stopped", "terminated", "archived", "disconnected", "unknown"}),
		"health":            stateReportDefinition("health", []string{"healthy", "degraded", "unreachable", "unknown"}),
		"extensions":        extensionsSchema(),
	})
}

func runtimeListSessionsResultDefinition() map[string]any {
	return closedObject([]string{"sessions"}, map[string]any{"sessions": array(runtimeSessionDefinition(), 0, 4096, true)})
}

func runtimeSessionResultDefinition() map[string]any {
	return closedObject([]string{"session"}, map[string]any{"session": runtimeSessionDefinition()})
}

func runtimeSnapshotDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "snapshot_id", "digest", "created_at"}, map[string]any{
		"native_session_id": nativeIDString(),
		"snapshot_id":       nativeIDString(),
		"digest":            digestSchema(),
		"created_at":        timestamp(),
	})
}

func terminalReadRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "after_offset", "maximum_bytes"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"after_offset":      integer(0),
		"maximum_bytes":     boundedInteger(1, protocol.MaxTerminalWindowBytes),
	})
}

func terminalSubscribeRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "after_offset", "window_bytes"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"after_offset":      integer(0),
		"window_bytes":      boundedInteger(1, protocol.MaxTerminalWindowBytes),
	})
}

func terminalInputRequestDefinition() map[string]any {
	value := closedObject([]string{"native_session_id", "stream_id", "encoding", "data"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"encoding":          enum("utf-8", "base64"),
		"data":              boundedString(1, 349_528),
	})
	value["allOf"] = terminalDataConstraints()
	return value
}

func terminalKeysRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "keys"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"keys":              array(boundedString(1, 64), 1, 64, false),
	})
}

func terminalResizeRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "rows", "columns"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"rows":              boundedInteger(1, 10_000),
		"columns":           boundedInteger(1, 10_000),
	})
}

func terminalDetachRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "subscription_id"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"subscription_id":   idString(),
	})
}

func terminalAckDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "stream_id", "sequence", "offset"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"sequence":          integer(1),
		"offset":            integer(0),
	})
}

func workspaceRequestDefinition() map[string]any {
	return closedObject([]string{"native_workspace_id"}, map[string]any{"native_workspace_id": nativeIDString()})
}

func workspaceCreateRequestDefinition() map[string]any {
	return closedObject([]string{"name", "configuration"}, map[string]any{
		"name":          boundedString(1, 256),
		"configuration": map[string]any{},
	})
}

func workspaceDefinition() map[string]any {
	return closedObject([]string{"provider_id", "native_workspace_id", "name", "extensions"}, map[string]any{
		"provider_id":         idString(),
		"native_workspace_id": nativeIDString(),
		"name":                boundedString(1, 256),
		"extensions":          extensionsSchema(),
	})
}

func workspaceListResultDefinition() map[string]any {
	return closedObject([]string{"workspaces"}, map[string]any{"workspaces": array(workspaceDefinition(), 0, 4096, true)})
}

func paneRequestDefinition() map[string]any {
	return closedObject([]string{"native_workspace_id", "native_pane_id"}, map[string]any{
		"native_workspace_id": nativeIDString(),
		"native_pane_id":      nativeIDString(),
	})
}

func paneCreateRequestDefinition() map[string]any {
	return closedObject([]string{"native_workspace_id", "rows", "columns"}, map[string]any{
		"native_workspace_id": nativeIDString(),
		"native_session_id":   nativeIDString(),
		"rows":                boundedInteger(1, 10_000),
		"columns":             boundedInteger(1, 10_000),
	})
}

func paneSplitRequestDefinition() map[string]any {
	properties := paneRequestDefinition()["properties"].(map[string]any)
	properties["direction"] = enum("horizontal", "vertical")
	return closedObject([]string{"native_workspace_id", "native_pane_id", "direction"}, properties)
}

func paneResizeRequestDefinition() map[string]any {
	properties := paneRequestDefinition()["properties"].(map[string]any)
	properties["rows"] = boundedInteger(1, 10_000)
	properties["columns"] = boundedInteger(1, 10_000)
	return closedObject([]string{"native_workspace_id", "native_pane_id", "rows", "columns"}, properties)
}

func paneDefinition() map[string]any {
	return closedObject([]string{"native_workspace_id", "native_pane_id", "rows", "columns"}, map[string]any{
		"native_workspace_id": nativeIDString(),
		"native_pane_id":      nativeIDString(),
		"native_session_id":   nativeIDString(),
		"rows":                boundedInteger(1, 10_000),
		"columns":             boundedInteger(1, 10_000),
	})
}

func paneListResultDefinition() map[string]any {
	return closedObject([]string{"panes"}, map[string]any{"panes": array(paneDefinition(), 0, 4096, true)})
}

func topologySnapshotDefinition() map[string]any {
	return closedObject([]string{"native_workspace_id", "revision", "observed_at", "panes"}, map[string]any{
		"native_workspace_id": nativeIDString(),
		"revision":            integer(1),
		"observed_at":         timestamp(),
		"panes":               array(paneDefinition(), 0, 4096, true),
	})
}

func harnessSessionRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id"}, map[string]any{"native_session_id": nativeIDString()})
}

func harnessLaunchRequestDefinition() map[string]any {
	return closedObject([]string{"native_environment_id", "context_version", "configuration", "configuration_digest"}, map[string]any{
		"native_environment_id": nativeIDString(),
		"native_runtime_id":     nativeIDString(),
		"context_version":       idString(),
		"configuration":         map[string]any{},
		"configuration_digest":  digestSchema(),
	})
}

func harnessResumeRequestDefinition() map[string]any {
	return closedObject([]string{"native_resume_reference", "context_version"}, map[string]any{
		"native_resume_reference": nativeIDString(),
		"context_version":         idString(),
	})
}

func harnessStateDefinition() map[string]any {
	return closedObject([]string{"provider_id", "native_session_id", "activity", "usage"}, map[string]any{
		"provider_id":       idString(),
		"native_session_id": nativeIDString(),
		"activity":          stateReportDefinition("activity", []string{"idle", "working", "waiting_for_user", "waiting_for_approval", "blocked", "done", "failed", "unknown"}),
		"usage":             usageDefinition(),
	})
}

func harnessSessionResultDefinition() map[string]any {
	return closedObject([]string{"provider_id", "native_session_id", "state"}, map[string]any{
		"provider_id":             idString(),
		"native_session_id":       nativeIDString(),
		"native_resume_reference": nativeIDString(),
		"state":                   harnessStateDefinition(),
	})
}

func harnessListResultDefinition() map[string]any {
	return closedObject([]string{"sessions"}, map[string]any{"sessions": array(harnessSessionResultDefinition(), 0, 4096, true)})
}

func agentMessageRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "message", "message_digest"}, map[string]any{
		"native_session_id": nativeIDString(),
		"message":           map[string]any{},
		"message_digest":    digestSchema(),
	})
}

func agentStateResultDefinition() map[string]any {
	return closedObject([]string{"state"}, map[string]any{"state": harnessStateDefinition()})
}

func agentToolDefinition() map[string]any {
	return closedObject([]string{"name", "input_schema"}, map[string]any{
		"name":         tokenString(1, 128),
		"description":  boundedString(1, 512),
		"input_schema": map[string]any{},
	})
}

func agentToolsResultDefinition() map[string]any {
	return closedObject([]string{"tools"}, map[string]any{"tools": array(agentToolDefinition(), 0, 256, true)})
}

func agentNativeIdentityResultDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "native_agent_id"}, map[string]any{
		"native_session_id": nativeIDString(),
		"native_agent_id":   nativeIDString(),
	})
}

func contextDeliverRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "context_version", "source_digest", "delivery_mode", "content", "content_digest"}, map[string]any{
		"native_session_id": nativeIDString(),
		"context_version":   idString(),
		"source_digest":     digestSchema(),
		"delivery_mode":     contextDeliveryModeDefinition(),
		"content":           map[string]any{},
		"content_digest":    digestSchema(),
	})
}

func contextConfirmRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id", "context_version"}, map[string]any{
		"native_session_id": nativeIDString(),
		"context_version":   idString(),
	})
}

func approvalListRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id"}, map[string]any{"native_session_id": nativeIDString()})
}

func providerApprovalRequestDefinition() map[string]any {
	return closedObject([]string{"native_approval_id", "native_session_id", "type", "summary", "risk", "requested_scopes", "request_digest", "revision", "expires_at"}, map[string]any{
		"native_approval_id": nativeIDString(),
		"native_session_id":  nativeIDString(),
		"type":               tokenString(1, 128),
		"summary":            boundedString(1, 512),
		"risk":               enum("low", "medium", "high", "critical"),
		"requested_scopes":   array(safeASCIIString(1, 128), 1, 64, true),
		"request_digest":     digestSchema(),
		"revision":           integer(1),
		"expires_at":         timestamp(),
	})
}

func approvalActionRequestDefinition(name protocol.CapabilityName) map[string]any {
	var outcome string
	switch name {
	case "approval.approve":
		outcome = "approved"
	case "approval.reject":
		outcome = "rejected"
	case "approval.expire":
		outcome = "expired"
	default:
		panic(fmt.Sprintf("approval action schema missing for %s", name))
	}
	return closedObject([]string{"native_session_id", "native_approval_id", "outcome", "expected_revision", "decision_digest"}, map[string]any{
		"native_session_id":  nativeIDString(),
		"native_approval_id": nativeIDString(),
		"outcome":            constant(outcome),
		"expected_revision":  integer(1),
		"decision_digest":    digestSchema(),
	})
}

func approvalListResultDefinition() map[string]any {
	return closedObject([]string{"approvals"}, map[string]any{"approvals": array(providerApprovalRequestDefinition(), 0, 1024, true)})
}

func artifactListRequestDefinition() map[string]any {
	return closedObject([]string{"native_session_id"}, map[string]any{"native_session_id": nativeIDString()})
}

func artifactListResultDefinition() map[string]any {
	return closedObject([]string{"artifacts"}, map[string]any{"artifacts": array(providerArtifactReportDefinition("#/components/schemas/ProviderLocalValue"), 0, 4096, true)})
}

func objectSchema(id, title string, required []string, properties, definitions map[string]any, constraints ...any) map[string]any {
	document := map[string]any{
		"$schema":              schemaVersion,
		"$id":                  id,
		"title":                title,
		"type":                 "object",
		"required":             required,
		"properties":           properties,
		"additionalProperties": true,
	}
	if len(definitions) != 0 {
		document["$defs"] = definitions
	}
	if len(constraints) != 0 {
		document["allOf"] = constraints
	}
	return document
}

func closedObject(required []string, properties map[string]any, constraints ...any) map[string]any {
	value := map[string]any{
		"type":                 "object",
		"properties":           properties,
		"additionalProperties": false,
	}
	if len(required) != 0 {
		value["required"] = required
	}
	if len(constraints) != 0 {
		value["allOf"] = constraints
	}
	return value
}

func platformDefinition() map[string]any {
	return closedObject([]string{"os", "architecture"}, map[string]any{
		"os":           tokenString(1, 128),
		"architecture": tokenString(1, 128),
	})
}

func capabilityDefinition() map[string]any {
	variants := make([]any, 0, len(protocol.KnownCapabilities())+1)
	for _, capability := range protocol.KnownCapabilities() {
		properties := map[string]any{
			"name":     constant(string(capability.Name)),
			"role":     constant(string(capability.Role)),
			"required": map[string]any{"type": "boolean"},
		}
		required := []string{"name", "role"}
		if capability.Mutating {
			properties["mutating"] = constant(true)
			properties["delivery_class"] = constant(string(capability.DeliveryClass))
			required = append(required, "mutating", "delivery_class")
		} else {
			properties["mutating"] = constant(false)
		}
		variants = append(variants, closedObject(required, properties))
	}
	extension := closedObject([]string{"name", "role"}, map[string]any{
		"name":           map[string]any{"type": "string", "pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,127}$`},
		"role":           enum("provider", "agent-harness", "session-runtime", "execution-environment", "orchestration"),
		"required":       map[string]any{"type": "boolean"},
		"mutating":       map[string]any{"type": "boolean"},
		"delivery_class": enum("provider_idempotent", "state_reconciled", "at_most_once"),
	}, map[string]any{
		"if":   map[string]any{"properties": map[string]any{"mutating": constant(true)}, "required": []string{"mutating"}},
		"then": map[string]any{"required": []string{"delivery_class"}},
		"else": map[string]any{"not": map[string]any{"required": []string{"delivery_class"}}},
	})
	variants = append(variants, extension)
	return map[string]any{"oneOf": variants}
}

func providerBindingDefinition() map[string]any {
	return closedObject([]string{"provider_id", "provider_version", "native_id", "artifact_digest"}, map[string]any{
		"provider_id":             idString(),
		"provider_version":        versionString(),
		"native_id":               nativeIDString(),
		"native_resume_reference": nativeIDString(),
		"artifact_digest":         digestSchema(),
	})
}

func stateReportDefinition(axis string, states []string) map[string]any {
	values := make([]any, len(states))
	for i, state := range states {
		values[i] = state
	}
	return closedObject([]string{"axis", "state", "source", "observed_at", "sequence", "confidence", "authority"}, map[string]any{
		"axis":        constant(axis),
		"state":       map[string]any{"type": "string", "enum": values},
		"source":      textString(1, 128),
		"observed_at": timestamp(),
		"sequence":    integer(1),
		"confidence":  map[string]any{"type": "number", "minimum": 0, "maximum": 1},
		"expires_at":  timestamp(),
		"authority":   enum("authoritative", "inferred"),
		"status":      boundedString(0, 1024),
	})
}

func contextReceiptDefinition() map[string]any {
	return closedObject([]string{"protocol_version", "session_id", "provider_id", "native_session_id", "context_version", "source_digest", "delivery_mode", "delivered_at", "status", "native_runtime_may_ignore"}, map[string]any{
		"protocol_version":          constant(protocol.ProtocolVersion),
		"session_id":                idString(),
		"provider_id":               idString(),
		"native_session_id":         nativeIDString(),
		"context_version":           idString(),
		"source_digest":             digestSchema(),
		"delivery_mode":             contextDeliveryModeDefinition(),
		"delivered_at":              timestamp(),
		"status":                    enum("accepted", "rejected", "failed"),
		"native_runtime_may_ignore": map[string]any{"type": "boolean"},
	})
}

func artifactDefinition() map[string]any {
	value := closedObject([]string{"protocol_version", "artifact_id", "session_id", "creator_type", "creator_id", "version", "review_state", "locality", "locator", "mime_type", "size", "digest", "classification", "source_resources", "extensions"}, map[string]any{
		"protocol_version": constant(protocol.ProtocolVersion),
		"artifact_id":      idString(),
		"session_id":       idString(),
		"creator_type":     enum("agent", "human", "workflow", "system"),
		"creator_id":       idString(),
		"version":          versionString(),
		"review_state":     enum("pending", "approved", "rejected"),
		"locality":         enum("local-only", "upload-eligible", "hosted"),
		"locator":          artifactLocator("local-resource", "artifact"),
		"mime_type":        boundedString(1, 256),
		"size":             integer(0),
		"digest":           digestSchema(),
		"classification":   enum("public", "metadata", "internal", "confidential", "restricted"),
		"source_resources": array(idString(), 0, 256, true),
		"extensions":       extensionsSchema(),
	})
	value["allOf"] = []any{
		localityLocatorConstraint([]string{"local-only", "upload-eligible"}, "local-resource"),
		localityLocatorConstraint([]string{"hosted"}, "artifact"),
	}
	return value
}

func providerArtifactReportDefinition(providerLocalReference string) map[string]any {
	return closedObject([]string{"protocol_version", "report_id", "provider_id", "role", "stream_id", "native_artifact_id", "version", "locality", "locator", "mime_type", "size", "digest", "source_locators", "extensions"}, map[string]any{
		"protocol_version":   constant(protocol.ProtocolVersion),
		"report_id":          idString(),
		"provider_id":        idString(),
		"role":               enum("agent-harness", "session-runtime", "execution-environment", "orchestration"),
		"stream_id":          idString(),
		"native_session_id":  nativeIDString(),
		"native_artifact_id": nativeIDString(),
		"version":            versionString(),
		"locality":           enum("local-only", "upload-eligible"),
		"locator":            artifactLocator("local-resource"),
		"mime_type":          boundedString(1, 256),
		"size":               integer(0),
		"digest":             digestSchema(),
		"source_locators":    array(artifactLocator("local-resource"), 0, 256, true),
		"extensions":         providerExtensionsSchema(providerLocalReference),
	})
}

func terminalChunkDefinition() map[string]any {
	value := closedObject([]string{"native_session_id", "stream_id", "encoding", "sequence", "offset", "observed_at", "data", "replayed", "truncated", "redactions", "credit_remaining"}, map[string]any{
		"native_session_id": nativeIDString(),
		"stream_id":         idString(),
		"encoding":          enum("utf-8", "base64"),
		"sequence":          integer(1),
		"offset":            integer(0),
		"observed_at":       timestamp(),
		"data":              boundedString(1, 349528),
		"replayed":          map[string]any{"type": "boolean"},
		"truncated":         map[string]any{"type": "boolean"},
		"redactions":        array(closedObject([]string{"start", "end", "reason"}, map[string]any{"start": integer(0), "end": integer(1), "reason": boundedString(1, 128)}), 0, 1024, false),
		"credit_remaining":  boundedInteger(0, protocol.MaxTerminalWindowBytes),
	})
	value["allOf"] = terminalDataConstraints()
	return value
}

func terminalDataConstraints() []any {
	return []any{
		map[string]any{
			"if":   map[string]any{"properties": map[string]any{"encoding": constant("utf-8")}, "required": []string{"encoding"}},
			"then": map[string]any{"properties": map[string]any{"data": boundedString(1, protocol.MaxTerminalChunkBytes)}},
		},
		map[string]any{
			"if": map[string]any{"properties": map[string]any{"encoding": constant("base64")}, "required": []string{"encoding"}},
			"then": map[string]any{"properties": map[string]any{"data": map[string]any{
				"type":      "string",
				"minLength": 4,
				"maxLength": 349_528,
				"pattern":   `^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`,
			}}},
		},
	}
}

func usageDefinition() map[string]any {
	return closedObject([]string{"input_tokens", "output_tokens", "cost_microunits"}, map[string]any{
		"input_tokens": integer(0), "output_tokens": integer(0), "cost_microunits": integer(0),
	})
}

func approvalBindingDefinition() map[string]any {
	return closedObject([]string{"command_digest", "session_id", "session_revision", "work_item_revision", "resource_revision", "context_version", "policy_revision", "environment", "harness", "gateway_id", "scopes", "expires_at", "nonce"}, map[string]any{
		"command_digest":     digestSchema(),
		"session_id":         idString(),
		"session_revision":   integer(1),
		"work_item_revision": integer(1),
		"resource_revision":  integer(1),
		"context_version":    idString(),
		"policy_revision":    integer(1),
		"environment":        approvalProviderSelectionDefinition("execution-environment"),
		"runtime":            approvalProviderSelectionDefinition("session-runtime"),
		"harness":            approvalProviderSelectionDefinition("agent-harness"),
		"gateway_id":         idString(),
		"scopes":             array(safeASCIIString(1, 128), 1, 64, true),
		"expires_at":         timestamp(),
		"nonce":              nonceString(),
	})
}

func approvalProviderSelectionDefinition(role string) map[string]any {
	return closedObject([]string{"role", "provider"}, map[string]any{
		"role":     constant(role),
		"provider": artifactIdentityDefinition(),
	})
}

func approvalDecisionDefinition() map[string]any {
	return closedObject([]string{"protocol_version", "approval_id", "outcome", "binding", "decision_revision", "decided_at"}, map[string]any{
		"protocol_version":  constant(protocol.ProtocolVersion),
		"approval_id":       idString(),
		"outcome":           enum("approved", "rejected", "expired"),
		"binding":           approvalBindingDefinition(),
		"decision_revision": integer(1),
		"decided_at":        timestamp(),
	})
}

func verificationDefinition() map[string]any {
	value := closedObject([]string{"protocol_version", "evidence_id", "tier", "subject", "result", "reference", "issued_at", "expires_at", "trust_epoch", "signature"}, map[string]any{
		"protocol_version":   constant(protocol.ProtocolVersion),
		"evidence_id":        idString(),
		"tier":               enum("native_contract_tested", "live_verified"),
		"subject":            verificationSubjectDefinition(),
		"result":             enum("passed", "failed"),
		"reference":          typedReference(),
		"issued_at":          timestamp(),
		"expires_at":         timestamp(),
		"trust_epoch":        integer(1),
		"live_authorization": liveAuthorizationDefinition(),
		"live_receipt":       liveReceiptDefinition(),
		"signature":          signatureDefinition("contract-verification", "live-verification"),
	})
	value["allOf"] = []any{
		map[string]any{
			"if": map[string]any{"properties": map[string]any{"tier": constant("native_contract_tested")}, "required": []string{"tier"}},
			"then": map[string]any{
				"properties": map[string]any{"signature": signatureDefinition("contract-verification")},
				"not":        map[string]any{"anyOf": []any{map[string]any{"required": []string{"live_authorization"}}, map[string]any{"required": []string{"live_receipt"}}}},
			},
		},
		map[string]any{
			"if": map[string]any{"properties": map[string]any{"tier": constant("live_verified")}, "required": []string{"tier"}},
			"then": map[string]any{
				"required":   []string{"live_authorization", "live_receipt"},
				"properties": map[string]any{"signature": signatureDefinition("live-verification")},
			},
		},
	}
	return value
}

func evidenceDefinition(kind string) map[string]any {
	binding := isolationBindingDefinition()
	purpose := "isolation-evidence"
	if kind == "custody" {
		binding = custodyBindingDefinition()
		purpose = "custody-evidence"
	}
	return closedObject([]string{"protocol_version", "evidence_id", "nonce", "binding", "issued_at", "expires_at", "signature"}, map[string]any{
		"protocol_version": constant(protocol.ProtocolVersion),
		"evidence_id":      idString(),
		"nonce":            nonceString(),
		"binding":          binding,
		"issued_at":        timestamp(),
		"expires_at":       timestamp(),
		"signature":        signatureDefinition(purpose),
	})
}

func artifactIdentityDefinition() map[string]any {
	return closedObject([]string{"id", "version", "digest"}, map[string]any{
		"id":      idString(),
		"version": safeVersionString(),
		"digest":  digestSchema(),
	})
}

func evidenceBindingProperties() map[string]any {
	return map[string]any{
		"session_id":            idString(),
		"policy_revision":       integer(1),
		"gateway_id":            idString(),
		"gateway_key_id":        idString(),
		"provider":              artifactIdentityDefinition(),
		"native_environment_id": nativeIDString(),
		"configuration_digest":  digestSchema(),
		"image_digest":          digestSchema(),
		"controls":              array(safeASCIIString(1, 128), 1, 128, true),
		"data_mode":             dataModeDefinition(),
	}
}

func isolationBindingDefinition() map[string]any {
	return closedObject([]string{"session_id", "policy_revision", "gateway_id", "gateway_key_id", "provider", "native_environment_id", "configuration_digest", "image_digest", "controls", "data_mode"}, evidenceBindingProperties())
}

func custodyBindingDefinition() map[string]any {
	return closedObject([]string{"session_id", "policy_revision", "gateway_id", "gateway_key_id", "provider", "native_environment_id", "configuration_digest", "image_digest", "controls", "data_mode"}, evidenceBindingProperties())
}

func verificationSubjectDefinition() map[string]any {
	return closedObject([]string{"provider", "native_artifact", "platform", "capabilities", "cases", "suite_version", "suite_digest", "configuration_digest", "data_modes"}, map[string]any{
		"provider":             artifactIdentityDefinition(),
		"native_artifact":      artifactIdentityDefinition(),
		"platform":             platformDefinition(),
		"capabilities":         array(capabilityNameString(), 1, 256, true),
		"cases":                array(safeASCIIString(1, 128), 1, 512, true),
		"suite_version":        safeVersionString(),
		"suite_digest":         digestSchema(),
		"configuration_digest": digestSchema(),
		"data_modes":           array(dataModeDefinition(), 1, 4, true),
	})
}

func liveAuthorizationDefinition() map[string]any {
	return closedObject([]string{"protocol_version", "authorization_id", "subject", "tenant_id", "gateway_id", "gateway_key_id", "correlation_id", "run_nonce", "budget_reference", "credential_reference", "issued_at", "expires_at", "trust_epoch", "signature"}, map[string]any{
		"protocol_version":     constant(protocol.ProtocolVersion),
		"authorization_id":     idString(),
		"subject":              verificationSubjectDefinition(),
		"tenant_id":            idString(),
		"gateway_id":           idString(),
		"gateway_key_id":       idString(),
		"correlation_id":       idString(),
		"run_nonce":            nonceString(),
		"budget_reference":     typedReference(),
		"credential_reference": typedReference(),
		"issued_at":            timestamp(),
		"expires_at":           timestamp(),
		"trust_epoch":          integer(1),
		"signature":            signatureDefinition("live-run-authorization"),
	})
}

func liveReceiptDefinition() map[string]any {
	return closedObject([]string{"protocol_version", "receipt_id", "authorization_id", "subject", "tenant_id", "gateway_id", "correlation_id", "run_nonce", "budget_reference", "credential_reference", "result", "usage", "audit_event_id", "issued_at", "signature"}, map[string]any{
		"protocol_version":     constant(protocol.ProtocolVersion),
		"receipt_id":           idString(),
		"authorization_id":     idString(),
		"subject":              verificationSubjectDefinition(),
		"tenant_id":            idString(),
		"gateway_id":           idString(),
		"correlation_id":       idString(),
		"run_nonce":            nonceString(),
		"budget_reference":     typedReference(),
		"credential_reference": typedReference(),
		"result":               enum("passed", "failed"),
		"usage": closedObject([]string{"input_tokens", "output_tokens", "cost_microunits"}, map[string]any{
			"input_tokens": integer(0), "output_tokens": integer(0), "cost_microunits": integer(0),
		}),
		"audit_event_id": idString(),
		"issued_at":      timestamp(),
		"signature":      signatureDefinition("live-run-receipt"),
	})
}

func dataModeDefinition() map[string]any {
	return enum("full", "ephemeral-transcript", "metadata-only", "local-control")
}

func signatureDefinition(purposes ...string) map[string]any {
	purpose := boundedString(1, 128)
	if len(purposes) != 0 {
		purpose = enum(purposes...)
	}
	return closedObject([]string{"algorithm", "purpose", "issuer", "key_id", "value"}, map[string]any{
		"algorithm": constant("ed25519"),
		"purpose":   purpose,
		"issuer":    idString(),
		"key_id":    idString(),
		"value":     map[string]any{"type": "string", "pattern": `^[A-Za-z0-9_-]{86}$`},
	})
}

func extensionsSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"propertyNames":        map[string]any{"pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,63}$`},
		"additionalProperties": true,
		"maxProperties":        64,
	}
}

func providerExtensionsSchema(providerLocalReference string) map[string]any {
	value := extensionsSchema()
	value["additionalProperties"] = ref(providerLocalReference)
	return value
}

func providerLocalValueDefinition(providerLocalReference string) map[string]any {
	reserved := append(providerReservedAuthorityFields(), providerReservedReviewFields()...)
	return map[string]any{
		"oneOf": []any{
			map[string]any{
				"type":                 "object",
				"propertyNames":        map[string]any{"not": enum(reserved...)},
				"additionalProperties": ref(providerLocalReference),
			},
			map[string]any{"type": "array", "items": ref(providerLocalReference)},
			map[string]any{"type": "string"},
			map[string]any{"type": "number"},
			map[string]any{"type": "boolean"},
			map[string]any{"type": "null"},
		},
	}
}

func providerAuthorityExclusion() map[string]any {
	reserved := providerReservedAuthorityFields()
	clauses := make([]any, 0, len(reserved))
	for _, field := range reserved {
		clauses = append(clauses, map[string]any{"required": []string{field}})
	}
	return map[string]any{"not": map[string]any{"anyOf": clauses}}
}

func providerReservedAuthorityFields() []string {
	return []string{"tenant_id", "project_id", "initiative_id", "work_item_id", "gateway_id", "session_id", "canonical_session_id", "correlation_id", "causation_id", "sensitivity", "authority", "verification_tier", "tier", "verified"}
}

func providerReservedReviewFields() []string {
	return []string{"artifact_id", "creator_type", "creator_id", "review_state", "classification", "approval_id", "approved", "decision_revision"}
}

func constant(value any) map[string]any {
	return map[string]any{"const": value}
}

func enum(values ...string) map[string]any {
	items := make([]any, len(values))
	for i, value := range values {
		items[i] = value
	}
	return map[string]any{"type": "string", "enum": items}
}

func boundedString(minimum, maximum int) map[string]any {
	return map[string]any{"type": "string", "minLength": minimum, "maxLength": maximum}
}

func textString(minimum, maximum int) map[string]any {
	value := boundedString(minimum, maximum)
	value["pattern"] = `^[^\x00\r\n]+$`
	return value
}

func executableString() map[string]any {
	value := textString(1, 256)
	value["pattern"] = `^[^/\\\x00\r\n]+$`
	value["not"] = enum(".", "..")
	return value
}

func idString() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 1,
		"maxLength": 128,
		"pattern":   `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
	}
}

func versionString() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 1,
		"maxLength": 128,
		"pattern":   `^[^\x00\r\n\t ]+$`,
	}
}

func safeVersionString() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 1,
		"maxLength": 128,
		"pattern":   `^[A-Za-z0-9._:/@+~=\-]+$`,
	}
}

func nativeIDString() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 1,
		"maxLength": protocol.MaxNativeIDBytes,
		"pattern":   `^[^\x00\r\n]+$`,
	}
}

func nonceString() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 22,
		"maxLength": 256,
		"pattern":   `^[A-Za-z0-9_-]{22,256}$`,
	}
}

func typedReference() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 3,
		"maxLength": 1024,
		"pattern":   `^[A-Za-z0-9._/@+~=\-]+:[A-Za-z0-9._:/@+~=\-]*$`,
	}
}

func opaqueReference() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 2,
		"maxLength": 1024,
		"pattern":   `^[^\x00\r\n]+:[^\x00\r\n]*$`,
	}
}

func localSchemaReference() map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": 1,
		"maxLength": 512,
		"pattern":   `^[A-Za-z0-9][A-Za-z0-9._/-]*$`,
		"not":       map[string]any{"pattern": `\.\.`},
	}
}

func capabilityNameString() map[string]any {
	known := protocol.KnownCapabilities()
	values := make([]any, 0, len(known))
	for _, capability := range known {
		values = append(values, string(capability.Name))
	}
	return map[string]any{
		"oneOf": []any{
			map[string]any{"type": "string", "enum": values},
			map[string]any{"type": "string", "pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,127}$`},
		},
	}
}

func providerEventTypeString() map[string]any {
	values := protocol.KnownProviderEventTypes()
	core := make([]any, len(values))
	for index, value := range values {
		core[index] = value
	}
	return map[string]any{
		"oneOf": []any{
			map[string]any{"type": "string", "enum": core},
			map[string]any{"type": "string", "pattern": `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+/[a-z][a-z0-9._-]{0,63}$`},
		},
	}
}

func safeASCIIString(minimum, maximum int) map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": minimum,
		"maxLength": maximum,
		"pattern":   `^[A-Za-z0-9._:/@+~=\-]+$`,
	}
}

func tokenString(minimum, maximum int) map[string]any {
	return map[string]any{
		"type":      "string",
		"minLength": minimum,
		"maxLength": maximum,
		"pattern":   `^[a-z0-9][a-z0-9._-]*$`,
	}
}

func integer(minimum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum}
}

func boundedInteger(minimum, maximum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum, "maximum": maximum}
}

func timestamp() map[string]any {
	return map[string]any{"type": "string", "format": "date-time", "pattern": `Z$`}
}

func digestSchema() map[string]any {
	return map[string]any{"type": "string", "pattern": `^sha256:[0-9a-f]{64}$`}
}

func array(items any, minimum, maximum int, unique bool) map[string]any {
	return map[string]any{"type": "array", "items": items, "minItems": minimum, "maxItems": maximum, "uniqueItems": unique}
}

func contextDeliveryModeDefinition() map[string]any {
	return enum("initial_prompt", "system_instructions", "mounted_file", "environment_reference", "mcp_resource", "acp_initialization", "project_instructions", "follow_up_message")
}

func artifactLocator(schemes ...string) map[string]any {
	parts := make([]any, 0, len(schemes))
	for _, scheme := range schemes {
		parts = append(parts, map[string]any{
			"type":      "string",
			"maxLength": 2048,
			"pattern":   `^` + scheme + `://[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
		})
	}
	if len(parts) == 1 {
		return parts[0].(map[string]any)
	}
	return map[string]any{"oneOf": parts}
}

func localityLocatorConstraint(localities []string, scheme string) map[string]any {
	return map[string]any{
		"if": map[string]any{
			"properties": map[string]any{"locality": enum(localities...)},
			"required":   []string{"locality"},
		},
		"then": map[string]any{"properties": map[string]any{"locator": artifactLocator(scheme)}},
	}
}

func ref(path string) map[string]any {
	return map[string]any{"$ref": path}
}
