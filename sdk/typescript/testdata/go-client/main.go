package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "typescript_interop_client_failed")
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := provider.NewClient(os.Stdin, os.Stdout, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	required := []protocol.CapabilityName{
		"provider.initialize",
		"provider.capabilities",
		"runtime.create_session",
		"runtime.stop_session",
		"terminal.subscribe",
	}
	initialized, err := client.Initialize(ctx, protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.Version},
		GatewayVersion:            "1.0.0",
		Platform:                  protocol.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		RequiredCapabilities:      required,
		MaximumMessageBytes:       provider.TestLimits().MaxEnvelopeBytes,
		MaximumChunkBytes:         provider.TestLimits().MaxEnvelopeBytes,
		ReplaySupported:           true,
		AuthenticationModes:       []string{"none"},
		ExperimentalFeatures:      []string{},
	})
	if err != nil || initialized.Manifest.ID != "typescript-reference" {
		return fmt.Errorf("initialize")
	}
	capabilities, err := client.Capabilities(ctx)
	if err != nil || len(capabilities.Capabilities) != len(initialized.Manifest.Capabilities) {
		return fmt.Errorf("capabilities")
	}

	configuration := json.RawMessage(`{}`)
	create := command("typescript-create-command", "typescript-create-idempotency", "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-typescript", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "typescript-environment",
		Name:                "TypeScript fixture",
		Configuration:       configuration,
		ConfigurationDigest: digest(configuration),
	})
	var created protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, create, &created); err != nil || created.Session.NativeSessionID != "typescript-native-session" {
		return fmt.Errorf("create")
	}

	subscription, err := client.SubscribeTerminal(ctx, protocol.TerminalSubscribeRequest{
		NativeSessionID: created.Session.NativeSessionID,
		StreamID:        "stdout",
		WindowBytes:     1024,
	})
	if err != nil || subscription.SubscriptionID != "typescript-terminal-subscription" {
		return fmt.Errorf("subscribe")
	}
	if err := waitForReplay(ctx, client.Notifications()); err != nil {
		return err
	}

	var unsupported protocol.RuntimeSessionResult
	if err := client.Query(ctx, "runtime.get_session", protocol.RuntimeSessionRequest{NativeSessionID: created.Session.NativeSessionID}, &unsupported); !protocol.IsCode(err, protocol.CodeNotSupported) {
		return fmt.Errorf("not_supported")
	}

	stop := command("typescript-stop-command", "typescript-stop-idempotency", "runtime.stop_session", protocol.DeliveryProviderIdempotent, "canonical-session-typescript", protocol.RuntimeSessionRequest{
		NativeSessionID: created.Session.NativeSessionID,
	})
	var stopped protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, stop, &stopped); err != nil || stopped.Session.Lifecycle.State != protocol.LifecycleStopped {
		return fmt.Errorf("stop")
	}
	return nil
}

func waitForReplay(ctx context.Context, notifications <-chan provider.Notification) error {
	for {
		select {
		case notification, ok := <-notifications:
			if !ok {
				return fmt.Errorf("notification_closed")
			}
			if notification.TerminalChunk != nil {
				chunk := notification.TerminalChunk
				if chunk.Replayed && chunk.Data == "typescript-ready" && chunk.Sequence == 1 {
					return nil
				}
				return fmt.Errorf("terminal_replay")
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func command(commandID, idempotency string, capability protocol.CapabilityName, delivery protocol.DeliveryClass, sessionID string, payload any) protocol.Command {
	raw, err := json.Marshal(payload)
	if err != nil {
		panic("static command payload")
	}
	return protocol.Command{
		ProtocolVersion:   protocol.Version,
		CommandID:         commandID,
		SessionID:         sessionID,
		Capability:        capability,
		IdempotencyKey:    idempotency,
		CancellationToken: commandID + "-cancel",
		Deadline:          time.Now().Add(5 * time.Second).UTC(),
		DeliveryClass:     delivery,
		Payload:           raw,
	}
}

func digest(data []byte) protocol.Digest {
	sum := sha256.Sum256(data)
	return protocol.Digest("sha256:" + hex.EncodeToString(sum[:]))
}
