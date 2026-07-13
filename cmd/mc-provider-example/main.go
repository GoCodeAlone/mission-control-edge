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
	manifest := protocol.ProviderManifest{
		ProtocolVersion:     protocol.Version,
		ID:                  "mission-example",
		Roles:               []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:                "Mission Control Example Provider",
		Version:             "1.0.0",
		Executable:          "mc-provider-example",
		Platforms:           []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities:        knownCapabilities("provider.initialize", "provider.health", "provider.capabilities", "provider.shutdown", "command.get_result"),
		InteractionModes:    []string{"json-rpc"},
		Permissions:         []string{},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
	handlers := provider.HandlerSet{Provider: provider.ProviderHandlers{
		Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
			return protocol.ProviderHealthResult{ProviderID: manifest.ID, Health: health()}, nil
		},
		Shutdown: func(context.Context, provider.MutationMeta, protocol.ProviderShutdownRequest) (protocol.OperationResult, error) {
			return protocol.OperationResult{OperationID: "example-shutdown", Status: protocol.OperationSucceeded, ObservedAt: time.Now().UTC()}, nil
		},
	}}
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, handlers)
	if err == nil {
		err = server.Serve(context.Background(), os.Stdin, os.Stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "provider_example_failed")
		os.Exit(1)
	}
}

func knownCapabilities(names ...protocol.CapabilityName) []protocol.CapabilityDescriptor {
	result := make([]protocol.CapabilityDescriptor, 0, len(names))
	for _, name := range names {
		capability, ok := protocol.Capability(name)
		if !ok {
			panic("unknown example capability")
		}
		result = append(result, capability)
	}
	return result
}

func health() protocol.StateReport {
	return protocol.StateReport{
		Axis: protocol.AxisHealth, State: protocol.HealthHealthy, Source: "example",
		ObservedAt: time.Now().UTC(), Sequence: 1, Confidence: 1, Authority: protocol.AuthorityAuthoritative,
	}
}
