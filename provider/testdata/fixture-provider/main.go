package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func main() {
	secretMarker := os.Getenv("MC_FIXTURE_SECRET_MARKER")
	if err := run(context.Background(), secretMarker); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fixture_provider_failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, secretMarker string) error {
	manifest := protocol.ProviderManifest{
		ProtocolVersion:     protocol.Version,
		ID:                  "fixture-provider",
		Roles:               []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:                "Fixture Provider",
		Version:             "1.0.0",
		Executable:          "fixture-provider",
		Platforms:           []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities:        capabilities("provider.initialize", "provider.health", "provider.capabilities", "provider.shutdown", "command.get_result", "runtime.create_session", "runtime.stop_session", "terminal.subscribe"),
		InteractionModes:    []string{"json-rpc"},
		Permissions:         []string{"local-process"},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
	now := time.Now().UTC()
	runtimeSession := protocol.RuntimeSession{
		ProviderID:      manifest.ID,
		NativeSessionID: "fixture-native-session",
		Lifecycle:       state(now, protocol.AxisLifecycle, protocol.LifecycleRunning),
		Health:          state(now, protocol.AxisHealth, protocol.HealthHealthy),
		Extensions:      map[string]json.RawMessage{},
	}
	handlers := provider.HandlerSet{
		Provider: provider.ProviderHandlers{
			Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
				return protocol.ProviderHealthResult{ProviderID: manifest.ID, Health: state(time.Now().UTC(), protocol.AxisHealth, protocol.HealthHealthy)}, nil
			},
			Shutdown: func(context.Context, provider.MutationMeta, protocol.ProviderShutdownRequest) (protocol.OperationResult, error) {
				return operation("fixture-shutdown"), nil
			},
		},
		Runtime: provider.RuntimeHandlers{
			Sessions: provider.RuntimeSessionHandlers{
				Create: func(_ context.Context, _ provider.MutationMeta, request protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
					if request.Name == "force-native-error" {
						return protocol.RuntimeSessionResult{}, fmt.Errorf("native failure contained %s", secretMarker)
					}
					return protocol.RuntimeSessionResult{Session: runtimeSession}, nil
				},
				Stop: func(context.Context, provider.MutationMeta, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
					stopped := runtimeSession
					stopped.Lifecycle = state(time.Now().UTC(), protocol.AxisLifecycle, protocol.LifecycleStopped)
					return protocol.RuntimeSessionResult{Session: stopped}, nil
				},
			},
			Terminal: provider.TerminalHandlers{
				Subscribe: func(context.Context, protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
					return provider.TerminalSubscription{
						Result: protocol.EventsSubscribeResult{SubscriptionID: "fixture-terminal-sub", Cursors: []protocol.EventSubscriptionCursor{}},
						Replay: []protocol.TerminalChunk{{
							NativeSessionID: runtimeSession.NativeSessionID,
							StreamID:        "stdout",
							Encoding:        protocol.TerminalEncodingUTF8,
							Sequence:        1,
							ObservedAt:      time.Now().UTC(),
							Data:            "fixture-ready",
							Replayed:        true,
							Redactions:      []protocol.TerminalRedaction{},
							CreditRemaining: 1011,
						}},
					}, nil
				},
			},
		},
	}
	server, err := provider.NewServer(provider.ServerConfig{
		Manifest:            manifest,
		AuthenticationModes: []string{"none"},
		ReplaySupported:     true,
	}, handlers, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		return err
	}
	return server.Serve(ctx, os.Stdin, os.Stdout)
}

func capabilities(names ...protocol.CapabilityName) []protocol.CapabilityDescriptor {
	result := make([]protocol.CapabilityDescriptor, 0, len(names))
	for _, name := range names {
		capability, ok := protocol.Capability(name)
		if !ok {
			panic("unknown fixture capability")
		}
		result = append(result, capability)
	}
	return result
}

func state(now time.Time, axis protocol.StateAxis, value protocol.State) protocol.StateReport {
	return protocol.StateReport{Axis: axis, State: value, Source: "fixture", ObservedAt: now, Sequence: 1, Confidence: 1, Authority: protocol.AuthorityAuthoritative}
}

func operation(id protocol.NativeID) protocol.OperationResult {
	return protocol.OperationResult{OperationID: id, Status: protocol.OperationSucceeded, ObservedAt: time.Now().UTC()}
}
