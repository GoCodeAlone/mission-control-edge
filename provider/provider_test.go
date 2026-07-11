package provider_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func TestExternalFixtureProviderOverStdio(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "fixture-provider")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./testdata/fixture-provider") // #nosec G204 -- test builds a fixed repository package into t.TempDir.
	build.Env = append(os.Environ(), "GOWORK=off")
	build.Dir = "."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}

	const secretMarker = "MC-SHOULD-NOT-LEAK-7d3e" // #nosec G101 -- synthetic redaction sentinel, not a credential.
	command := exec.CommandContext(ctx, binary)    // #nosec G204 -- binary is the fixed fixture just built into t.TempDir.
	command.Env = append(os.Environ(), "MC_FIXTURE_SECRET_MARKER="+secretMarker)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	client, err := provider.NewClient(io.TeeReader(stdout, &wire), stdin, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	manifest := testManifest(t,
		"provider.initialize",
		"provider.health",
		"provider.capabilities",
		"provider.shutdown",
		"command.get_result",
		"runtime.create_session",
		"runtime.stop_session",
		"terminal.subscribe",
	)
	manifest.Platforms = []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}}
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	leakProbe := testCommand(t, "external-leak-probe-1", "external-idempotency-leak-probe", "runtime.create_session", protocol.DeliveryStateReconciled, "external-session-1", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "environment-native-1",
		Name:                "force-native-error",
		Configuration:       json.RawMessage(`{}`),
		ConfigurationDigest: digest([]byte(`{}`)),
	})
	if err := client.Mutate(ctx, leakProbe, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeUnavailable) || strings.Contains(err.Error(), secretMarker) {
		t.Fatalf("secret-bearing native error was not redacted: %v", err)
	}

	create := testCommand(t, "external-create-1", "external-idempotency-create", "runtime.create_session", protocol.DeliveryStateReconciled, "external-session-1", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "environment-native-1",
		Configuration:       json.RawMessage(`{}`),
		ConfigurationDigest: digest([]byte(`{}`)),
	})
	var created protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, create, &created); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := client.SubscribeTerminal(ctx, protocol.TerminalSubscribeRequest{
		NativeSessionID: created.Session.NativeSessionID,
		StreamID:        "stdout",
		WindowBytes:     1024,
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	notification := waitNotification(t, client.Notifications(), provider.NotificationTerminalChunk, 2*time.Second)
	if notification.TerminalChunk == nil || !notification.TerminalChunk.Replayed {
		t.Fatalf("notification = %#v, want replay", notification)
	}

	stop := testCommand(t, "external-stop-1", "external-idempotency-stop", "runtime.stop_session", protocol.DeliveryProviderIdempotent, "external-session-1", protocol.RuntimeSessionRequest{NativeSessionID: created.Session.NativeSessionID})
	if err := client.Mutate(ctx, stop, &protocol.RuntimeSessionResult{}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	shutdown := testCommand(t, "external-shutdown-1", "external-idempotency-shutdown", "provider.shutdown", protocol.DeliveryProviderIdempotent, "", protocol.ProviderShutdownRequest{})
	if err := client.Mutate(ctx, shutdown, &protocol.OperationResult{}); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("fixture exit: %v; stderr=%q", err, stderr.String())
	}
	_ = client.Close()
	if bytes.Contains(wire.Bytes(), []byte(secretMarker)) || bytes.Contains(stderr.Bytes(), []byte(secretMarker)) {
		t.Fatal("secret marker leaked through SDK diagnostics or protocol output")
	}
}

func TestExampleProviderLaunchesThroughRealClient(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "mc-provider-example")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "../cmd/mc-provider-example") // #nosec G204 -- test builds a fixed repository package into t.TempDir.
	build.Env = append(os.Environ(), "GOWORK=off")
	build.Dir = "."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example: %v\n%s", err, output)
	}
	command := exec.CommandContext(ctx, binary) // #nosec G204 -- binary is the fixed example just built into t.TempDir.
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := provider.NewClient(stdout, stdin)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	manifest := testManifest(t, "provider.initialize", "provider.health", "provider.capabilities", "provider.shutdown", "command.get_result")
	manifest.ID = "mission-example"
	manifest.Name = "Mission Control Example Provider"
	manifest.Executable = "mc-provider-example"
	manifest.Permissions = []string{}
	manifest.Platforms = []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}}
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	health, err := client.Health(ctx)
	if err != nil || health.Health.State != protocol.HealthHealthy {
		t.Fatalf("Health = %#v, %v", health, err)
	}
	shutdown := testCommand(t, "example-shutdown-1", "example-idempotency-shutdown", "provider.shutdown", protocol.DeliveryProviderIdempotent, "", protocol.ProviderShutdownRequest{})
	if err := client.Mutate(ctx, shutdown, &protocol.OperationResult{}); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("example exit: %v; stderr=%q", err, stderr.String())
	}
	_ = client.Close()
}

func TestClientServerLifecycleReplayAndIdempotency(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t,
		"provider.initialize",
		"provider.health",
		"provider.capabilities",
		"provider.shutdown",
		"command.get_result",
		"runtime.create_session",
		"runtime.stop_session",
		"terminal.subscribe",
	)
	now := time.Now().UTC()
	session := testRuntimeSession(now, protocol.LifecycleRunning)
	chunk := protocol.TerminalChunk{
		NativeSessionID: session.NativeSessionID,
		StreamID:        "stdout",
		Encoding:        protocol.TerminalEncodingUTF8,
		Sequence:        1,
		Offset:          0,
		ObservedAt:      now,
		Data:            "fixture-ready",
		Replayed:        true,
		Redactions:      []protocol.TerminalRedaction{},
		CreditRemaining: 1011,
	}

	var creates atomic.Int32
	handlers := provider.HandlerSet{
		Provider: provider.ProviderHandlers{
			Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
				return protocol.ProviderHealthResult{ProviderID: manifest.ID, Health: testState(now, protocol.AxisHealth, protocol.HealthHealthy)}, nil
			},
			Shutdown: func(context.Context, provider.MutationMeta, protocol.ProviderShutdownRequest) (protocol.OperationResult, error) {
				return testOperation(now, "shutdown-op"), nil
			},
		},
		Runtime: provider.RuntimeHandlers{
			Sessions: provider.RuntimeSessionHandlers{
				Create: func(context.Context, provider.MutationMeta, protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
					creates.Add(1)
					return protocol.RuntimeSessionResult{Session: session}, nil
				},
				Stop: func(context.Context, provider.MutationMeta, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
					stopped := session
					stopped.Lifecycle = testState(now, protocol.AxisLifecycle, protocol.LifecycleStopped)
					return protocol.RuntimeSessionResult{Session: stopped}, nil
				},
			},
			Terminal: provider.TerminalHandlers{
				Subscribe: func(context.Context, protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
					return provider.TerminalSubscription{
						Result: protocol.EventsSubscribeResult{SubscriptionID: "terminal-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
						Replay: []protocol.TerminalChunk{chunk},
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
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(func() { _ = clientConn.Close() })
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ServeConn(ctx, serverConn) }()

	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	initRequest := testInitializeRequest(manifest)
	initialized, err := client.Initialize(ctx, initRequest)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if initialized.Manifest.ID != manifest.ID {
		t.Fatalf("provider ID = %q, want %q", initialized.Manifest.ID, manifest.ID)
	}

	capabilities, err := client.Capabilities(ctx)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if len(capabilities.Capabilities) != len(manifest.Capabilities) {
		t.Fatalf("capability count = %d, want %d", len(capabilities.Capabilities), len(manifest.Capabilities))
	}

	create := testCommand(t, "cmd-create-1", "stable-idempotency-create", "runtime.create_session", protocol.DeliveryStateReconciled, "session-canonical-1", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "environment-native-1",
		Name:                "fixture",
		Configuration:       json.RawMessage(`{}`),
		ConfigurationDigest: digest([]byte(`{}`)),
	})
	var created protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, create, &created); err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Session.NativeSessionID != session.NativeSessionID {
		t.Fatalf("native session = %q, want %q", created.Session.NativeSessionID, session.NativeSessionID)
	}
	var duplicate protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, create, &duplicate); err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
	if got := creates.Load(); got != 1 {
		t.Fatalf("create handler calls = %d, want 1", got)
	}

	conflict := create
	conflict.CommandID = "cmd-create-2"
	if err := client.Mutate(ctx, conflict, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("idempotency collision error = %v, want conflict", err)
	}

	subscription, err := client.SubscribeTerminal(ctx, protocol.TerminalSubscribeRequest{
		NativeSessionID: session.NativeSessionID,
		StreamID:        "stdout",
		AfterOffset:     0,
		WindowBytes:     1024,
	})
	if err != nil {
		t.Fatalf("SubscribeTerminal: %v", err)
	}
	if subscription.SubscriptionID != "terminal-sub-1" {
		t.Fatalf("subscription ID = %q", subscription.SubscriptionID)
	}
	notification := waitNotification(t, client.Notifications(), provider.NotificationTerminalChunk, 2*time.Second)
	if notification.TerminalChunk == nil {
		t.Fatalf("notification = %#v, want terminal chunk", notification)
	}
	if notification.TerminalChunk.Data != chunk.Data || !notification.TerminalChunk.Replayed {
		t.Fatalf("chunk = %#v, want replay %#v", notification.TerminalChunk, chunk)
	}

	var unsupported protocol.RuntimeSessionResult
	err = client.Query(ctx, "runtime.get_session", protocol.RuntimeSessionRequest{NativeSessionID: session.NativeSessionID}, &unsupported)
	if !protocol.IsCode(err, protocol.CodeNotSupported) {
		t.Fatalf("unsupported query error = %v, want not_supported", err)
	}

	stop := testCommand(t, "cmd-stop-1", "stable-idempotency-stop", "runtime.stop_session", protocol.DeliveryProviderIdempotent, "session-canonical-1", protocol.RuntimeSessionRequest{NativeSessionID: session.NativeSessionID})
	var stopped protocol.RuntimeSessionResult
	if err := client.Mutate(ctx, stop, &stopped); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if stopped.Session.Lifecycle.State != protocol.LifecycleStopped {
		t.Fatalf("stopped lifecycle = %q", stopped.Session.Lifecycle.State)
	}

	shutdown := testCommand(t, "cmd-shutdown-1", "stable-idempotency-shutdown", "provider.shutdown", protocol.DeliveryProviderIdempotent, "", protocol.ProviderShutdownRequest{})
	var shutdownResult protocol.OperationResult
	if err := client.Mutate(ctx, shutdown, &shutdownResult); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if shutdownResult.Status != protocol.OperationSucceeded {
		t.Fatalf("shutdown status = %q", shutdownResult.Status)
	}

	cancel()
	_ = client.Close()
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ServeConn: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestClientCancellationReachesHandler(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.health", "provider.capabilities")
	handlerCancelled := make(chan struct{})
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{
			Health: func(ctx context.Context, _ protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
				<-ctx.Done()
				close(handlerCancelled)
				return protocol.ProviderHealthResult{}, ctx.Err()
			},
		},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	serveCtx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go func() { _ = server.ServeConn(serveCtx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Initialize(serveCtx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	ctx, cancel := context.WithTimeout(serveCtx, 25*time.Millisecond)
	defer cancel()
	_, err = client.Health(ctx)
	if !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
		t.Fatalf("Health error = %v, want deadline_exceeded", err)
	}
	select {
	case <-handlerCancelled:
	case <-time.After(time.Second):
		t.Fatal("handler context was not cancelled")
	}
}

func TestClientDeadlineIsNotBlockedByTransportWrite(t *testing.T) {
	t.Parallel()

	clientConn, peerConn := net.Pipe()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	defer closeConnection(t, peerConn)
	manifest := testManifest(t, "provider.initialize", "provider.capabilities")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, initializeErr := client.Initialize(ctx, testInitializeRequest(manifest))
		done <- initializeErr
	}()
	select {
	case err := <-done:
		if !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
			t.Fatalf("Initialize error = %v, want deadline_exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		_ = peerConn.Close()
		t.Fatal("client deadline was blocked by a transport write")
	}
}

func TestEventSubscriptionReplaysAfterAcknowledgement(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "events.subscribe")
	now := time.Now().UTC()
	event := protocol.ProviderEvent{
		ProtocolVersion: protocol.Version,
		EventID:         "event-replay-1",
		ProviderID:      manifest.ID,
		Role:            protocol.RoleSessionRuntime,
		StreamID:        "runtime-events",
		NativeSessionID: "native-session-1",
		Type:            "session.discovered",
		Sequence:        1,
		ObservedAt:      now,
		Payload:         json.RawMessage(`{}`),
		Extensions:      map[string]json.RawMessage{},
	}
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}, ReplaySupported: true}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Events: provider.EventHandlers{
			Subscribe: func(context.Context, protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
				return provider.EventSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "event-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
					Replay: []protocol.ProviderEvent{event},
				}, nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	var result protocol.EventsSubscribeResult
	if err := client.Query(ctx, "events.subscribe", protocol.EventsSubscribeRequest{WindowSize: 1}, &result); err != nil {
		t.Fatalf("events.subscribe: %v", err)
	}
	if result.SubscriptionID != "event-sub-1" {
		t.Fatalf("subscription ID = %q", result.SubscriptionID)
	}
	notification := waitNotification(t, client.Notifications(), provider.NotificationEvent, time.Second)
	if notification.Event == nil || notification.Event.EventID != event.EventID {
		t.Fatalf("notification = %#v, want replay event", notification)
	}
}

func TestSubscriptionCapacityRejectsBeforeAcknowledgement(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "events.subscribe")
	live := make(chan protocol.ProviderEvent)
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Events: provider.EventHandlers{
			Subscribe: func(context.Context, protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
				calls.Add(1)
				return provider.EventSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "capacity-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
					Events: live,
				}, nil
			},
		}},
	}, provider.WithLimits(func() provider.Limits {
		limits := provider.TestLimits()
		limits.MaxSubscriptions = 1
		return limits
	}()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	request := protocol.EventsSubscribeRequest{WindowSize: 1}
	if err := client.Query(ctx, "events.subscribe", request, &protocol.EventsSubscribeResult{}); err != nil {
		t.Fatalf("first subscribe: %v", err)
	}
	if err := client.Query(ctx, "events.subscribe", request, &protocol.EventsSubscribeResult{}); !protocol.IsCode(err, protocol.CodeResourceExhausted) {
		t.Fatalf("second subscribe error = %v, want resource_exhausted", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("subscribe handler calls = %d, want 1", got)
	}
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("connection was lost after capacity rejection: %v", err)
	}
}

func TestSubscriptionContextPersistsUntilUnsubscribe(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "events.subscribe", "events.unsubscribe")
	live := make(chan protocol.ProviderEvent)
	subscriptionCancelled := make(chan int, 2)
	var subscriptions atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Events: provider.EventHandlers{
			Subscribe: func(ctx context.Context, _ protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
				subscription := int(subscriptions.Add(1))
				lifetime := provider.SubscriptionContext(ctx)
				go func() {
					<-lifetime.Done()
					subscriptionCancelled <- subscription
				}()
				return provider.EventSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "persistent-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
					Events: live,
				}, nil
			},
			Unsubscribe: func(context.Context, provider.MutationMeta, protocol.EventsUnsubscribeRequest) (protocol.OperationResult, error) {
				return testOperation(time.Now().UTC(), "unsubscribe-op"), nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := client.Query(ctx, "events.subscribe", protocol.EventsSubscribeRequest{WindowSize: 1}, &protocol.EventsSubscribeResult{}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	select {
	case subscription := <-subscriptionCancelled:
		t.Fatalf("subscription %d handler context ended with the request", subscription)
	case <-time.After(25 * time.Millisecond):
	}
	unsubscribe := testCommand(t, "unsubscribe-command-1", "unsubscribe-idempotency-1", "events.unsubscribe", protocol.DeliveryProviderIdempotent, "", protocol.EventsUnsubscribeRequest{SubscriptionID: "persistent-sub-1"})
	if err := client.Mutate(ctx, unsubscribe, &protocol.OperationResult{}); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}
	select {
	case subscription := <-subscriptionCancelled:
		if subscription != 1 {
			t.Fatalf("canceled subscription = %d, want 1", subscription)
		}
	case <-time.After(time.Second):
		t.Fatal("unsubscribe did not cancel the subscription context")
	}
	resubscribeDeadline := time.Now().Add(time.Second)
	for {
		err := client.Query(ctx, "events.subscribe", protocol.EventsSubscribeRequest{WindowSize: 1}, &protocol.EventsSubscribeResult{})
		if err == nil {
			break
		}
		if !protocol.IsCode(err, protocol.CodeConflict) || time.Now().After(resubscribeDeadline) {
			t.Fatalf("resubscribe with reused native ID: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	if err := client.Mutate(ctx, unsubscribe, &protocol.OperationResult{}); err != nil {
		t.Fatalf("cached unsubscribe retry: %v", err)
	}
	select {
	case subscription := <-subscriptionCancelled:
		t.Fatalf("cached unsubscribe retry canceled reused subscription %d", subscription)
	case <-time.After(25 * time.Millisecond):
	}
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("connection after cached unsubscribe retry: %v", err)
	}
}

func TestDuplicateTerminalAttachDoesNotConsumeSubscriptionCapacity(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "runtime.stop_session", "terminal.attach", "terminal.detach")
	chunks := make(chan protocol.TerminalChunk)
	var calls atomic.Int32
	var stopCalls atomic.Int32
	serverLimits := provider.TestLimits()
	serverLimits.MaxSubscriptions = 1
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			Stop: func(context.Context, provider.MutationMeta, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
				stopCalls.Add(1)
				return protocol.RuntimeSessionResult{Session: testRuntimeSession(time.Now().UTC(), protocol.LifecycleStopped)}, nil
			},
		}, Terminal: provider.TerminalHandlers{
			Attach: func(context.Context, provider.MutationMeta, protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
				calls.Add(1)
				return provider.TerminalSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "attach-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
					Chunks: chunks,
				}, nil
			},
			Detach: func(context.Context, provider.MutationMeta, provider.TerminalDetachRequest) (protocol.TerminalAck, error) {
				return protocol.TerminalAck{NativeSessionID: "native-session-1", StreamID: "stdout", Sequence: 1}, nil
			},
		}},
	}, provider.WithLimits(serverLimits))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	attach := testCommand(t, "attach-command-1", "attach-idempotency-1", "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 1024,
	})
	for attempt := 1; attempt <= 2; attempt++ {
		var result protocol.EventsSubscribeResult
		if err := client.Mutate(ctx, attach, &result); err != nil {
			t.Fatalf("attach attempt %d: %v", attempt, err)
		}
		if result.SubscriptionID != "attach-sub-1" {
			t.Fatalf("attach attempt %d subscription = %q", attempt, result.SubscriptionID)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("attach handler calls = %d, want 1", got)
	}
	commandIDCollision := testCommand(t, attach.CommandID, "different-idempotency-key", "runtime.stop_session", protocol.DeliveryProviderIdempotent, "canonical-session-1", protocol.RuntimeSessionRequest{NativeSessionID: "native-session-1"})
	if err := client.Mutate(ctx, commandIDCollision, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("cross-capability command ID collision error = %v, want conflict", err)
	}
	if stopCalls.Load() != 0 {
		t.Fatalf("command ID collision reached stop handler %d times", stopCalls.Load())
	}
	detach := testCommand(t, "detach-command-1", "detach-idempotency-1", "terminal.detach", protocol.DeliveryProviderIdempotent, "canonical-session-1", provider.TerminalDetachRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", SubscriptionID: "attach-sub-1",
	})
	for attempt := 1; attempt <= 2; attempt++ {
		if err := client.Mutate(ctx, detach, &protocol.TerminalAck{}); err != nil {
			t.Fatalf("detach attempt %d: %v", attempt, err)
		}
	}
}

func TestServerShutdownTimeoutBoundsNonCooperativeHandler(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.health", "provider.capabilities")
	started := make(chan struct{})
	release := make(chan struct{})
	limits := provider.TestLimits()
	limits.ShutdownTimeout = 50 * time.Millisecond
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
			close(started)
			<-release
			return protocol.ProviderHealthResult{}, errors.New("native handler ignored cancellation")
		}},
	}, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	serveCtx, stopServer := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.ServeConn(serveCtx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(context.Background(), testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	go func() { _, _ = client.Health(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("health handler did not start")
	}
	stopServer()
	select {
	case err := <-serveDone:
		if !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
			t.Fatalf("ServeConn error = %v, want deadline_exceeded", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("ServeConn exceeded its shutdown timeout")
	}
	close(release)
}

func TestTerminalWindowWaitsForExplicitCredit(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "terminal.subscribe")
	chunks := make(chan protocol.TerminalChunk)
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Terminal: provider.TerminalHandlers{
			Subscribe: func(context.Context, protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
				return provider.TerminalSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "credit-sub-1", Cursors: []protocol.EventSubscriptionCursor{}},
					Chunks: chunks,
				}, nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := client.SubscribeTerminal(ctx, protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 5}); err != nil {
		t.Fatalf("SubscribeTerminal: %v", err)
	}
	now := time.Now().UTC()
	chunks <- protocol.TerminalChunk{
		NativeSessionID: "native-session-1", StreamID: "stdout", Encoding: protocol.TerminalEncodingUTF8,
		Sequence: 1, Offset: 0, ObservedAt: now, Data: "12345", Redactions: []protocol.TerminalRedaction{}, CreditRemaining: 0,
	}
	first := waitNotification(t, client.Notifications(), provider.NotificationTerminalChunk, time.Second)
	if first.TerminalChunk == nil || first.TerminalChunk.Sequence != 1 {
		t.Fatalf("first terminal notification = %#v", first)
	}
	go func() {
		chunks <- protocol.TerminalChunk{
			NativeSessionID: "native-session-1", StreamID: "stdout", Encoding: protocol.TerminalEncodingUTF8,
			Sequence: 2, Offset: 5, ObservedAt: now.Add(time.Millisecond), Data: "6", Redactions: []protocol.TerminalRedaction{}, CreditRemaining: 0,
		}
	}()
	quiet := time.NewTimer(25 * time.Millisecond)
	defer quiet.Stop()
	for {
		select {
		case notification := <-client.Notifications():
			if notification.Method == provider.NotificationTerminalChunk {
				t.Fatal("second terminal chunk arrived before credit")
			}
		case <-quiet.C:
			goto grantCredit
		}
	}

grantCredit:
	if err := client.SendTerminalCredit(ctx, protocol.TerminalCredit{NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 1, ThroughOffset: 5}); err != nil {
		t.Fatalf("SendTerminalCredit: %v", err)
	}
	second := waitNotification(t, client.Notifications(), provider.NotificationTerminalChunk, time.Second)
	if second.TerminalChunk == nil || second.TerminalChunk.Sequence != 2 {
		t.Fatalf("second terminal notification = %#v", second)
	}
}

func TestNegotiatedChunkAndReplayLimitsAreEnforced(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "terminal.read", "events.subscribe")
	now := time.Now().UTC()
	event := protocol.ProviderEvent{
		ProtocolVersion: protocol.Version, EventID: "forbidden-replay-1", ProviderID: manifest.ID,
		Role: protocol.RoleSessionRuntime, StreamID: "runtime-events", NativeSessionID: "native-session-1",
		Type: "session.discovered", Sequence: 1, ObservedAt: now, Payload: json.RawMessage(`{}`), Extensions: map[string]json.RawMessage{},
	}
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}, ReplaySupported: false}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Events: provider.EventHandlers{
			Subscribe: func(context.Context, protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
				return provider.EventSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "replay-disabled-sub", Cursors: []protocol.EventSubscriptionCursor{}},
					Replay: []protocol.ProviderEvent{event},
				}, nil
			},
		}},
		Runtime: provider.RuntimeHandlers{Terminal: provider.TerminalHandlers{
			Read: func(context.Context, protocol.TerminalReadRequest) (protocol.TerminalChunk, error) {
				return protocol.TerminalChunk{
					NativeSessionID: "native-session-1", StreamID: "stdout", Encoding: protocol.TerminalEncodingUTF8,
					Sequence: 1, ObservedAt: now, Data: "12345", Redactions: []protocol.TerminalRedaction{}, CreditRemaining: 0,
				}, nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	initialize := testInitializeRequest(manifest)
	initialize.MaximumChunkBytes = 4
	initialize.ReplaySupported = false
	if _, err := client.Initialize(ctx, initialize); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	var chunk protocol.TerminalChunk
	err = client.Query(ctx, "terminal.read", protocol.TerminalReadRequest{NativeSessionID: "native-session-1", StreamID: "stdout", MaximumBytes: 5}, &chunk)
	if !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("terminal.read error = %v, want message_too_large", err)
	}
	err = client.Query(ctx, "events.subscribe", protocol.EventsSubscribeRequest{WindowSize: 1}, &protocol.EventsSubscribeResult{})
	if !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("events.subscribe replay error = %v, want invalid_argument", err)
	}
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("connection lost after negotiated-limit errors: %v", err)
	}
}

func TestNamespacedExtensionCapabilityDispatches(t *testing.T) {
	t.Parallel()

	const capability protocol.CapabilityName = "dev.gocodealone.mission-control/echo"
	manifest := testManifest(t, "provider.initialize", "provider.capabilities")
	manifest.Capabilities = append(manifest.Capabilities, protocol.CapabilityDescriptor{Name: capability, Role: protocol.RoleSessionRuntime})
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Extensions: map[protocol.CapabilityName]provider.ExtensionHandlers{
			capability: {Query: func(_ context.Context, request json.RawMessage) (json.RawMessage, error) {
				if string(request) != `{"value":"hello"}` {
					return nil, errors.New("unexpected extension request")
				}
				return json.RawMessage(`{"accepted":true}`), nil
			}},
		},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	var result json.RawMessage
	if err := client.Query(ctx, capability, json.RawMessage(`{"value":"hello"}`), &result); err != nil {
		t.Fatalf("extension query: %v", err)
	}
	if string(result) != `{"accepted":true}` {
		t.Fatalf("extension result = %s", result)
	}
}

func TestClosedRequestDecodeErrorsAreInvalidArguments(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "runtime.get_session")
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			Get: func(context.Context, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
				calls.Add(1)
				return protocol.RuntimeSessionResult{}, errors.New("must not run")
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	for name, request := range map[string]json.RawMessage{
		"unknown field":   json.RawMessage(`{"native_session_id":"native-session-1","unexpected":true}`),
		"malformed field": json.RawMessage(`{"native_session_id":42}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := client.Query(ctx, "runtime.get_session", request, &protocol.RuntimeSessionResult{})
			if !protocol.IsCode(err, protocol.CodeInvalidArgument) {
				t.Fatalf("runtime.get_session error = %v, want invalid_argument", err)
			}
		})
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("handler calls = %d, want 0", got)
	}
}

func TestRuntimeAndWorkspaceResultsRejectReservedExtensionAuthority(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t,
		"provider.initialize",
		"provider.capabilities",
		"runtime.list_sessions",
		"runtime.get_session",
		"workspace.list",
		"workspace.get",
	)
	now := time.Now().UTC()
	session := testRuntimeSession(now, protocol.LifecycleRunning)
	session.Extensions = map[string]json.RawMessage{
		"dev.example.runtime/metadata": json.RawMessage(`{"nested":{"session_id":"forged-session"}}`),
	}
	workspace := protocol.Workspace{
		ProviderID:        manifest.ID,
		NativeWorkspaceID: "native-workspace-1",
		Name:              "Workspace",
		Extensions: map[string]json.RawMessage{
			"dev.example.runtime/metadata": json.RawMessage(`{"nested":{"authority":"forged-authority"}}`),
		},
	}
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{
			Sessions: provider.RuntimeSessionHandlers{
				List: func(context.Context, protocol.RuntimeListSessionsRequest) (protocol.RuntimeListSessionsResult, error) {
					return protocol.RuntimeListSessionsResult{Sessions: []protocol.RuntimeSession{session}}, nil
				},
				Get: func(context.Context, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
					return protocol.RuntimeSessionResult{Session: session}, nil
				},
			},
			Workspaces: provider.WorkspaceHandlers{
				List: func(context.Context, provider.WorkspaceListRequest) (protocol.WorkspaceListResult, error) {
					return protocol.WorkspaceListResult{Workspaces: []protocol.Workspace{workspace}}, nil
				},
				Get: func(context.Context, protocol.WorkspaceRequest) (protocol.Workspace, error) {
					return workspace, nil
				},
			},
		},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	queries := []struct {
		name       string
		capability protocol.CapabilityName
		request    any
		result     any
	}{
		{name: "runtime session", capability: "runtime.get_session", request: protocol.RuntimeSessionRequest{NativeSessionID: session.NativeSessionID}, result: &protocol.RuntimeSessionResult{}},
		{name: "runtime session list", capability: "runtime.list_sessions", request: protocol.RuntimeListSessionsRequest{}, result: &protocol.RuntimeListSessionsResult{}},
		{name: "workspace", capability: "workspace.get", request: protocol.WorkspaceRequest{NativeWorkspaceID: workspace.NativeWorkspaceID}, result: &protocol.Workspace{}},
		{name: "workspace list", capability: "workspace.list", request: provider.WorkspaceListRequest{}, result: &protocol.WorkspaceListResult{}},
	}
	for _, query := range queries {
		t.Run(query.name, func(t *testing.T) {
			err := client.Query(ctx, query.capability, query.request, query.result)
			if !protocol.IsCode(err, protocol.CodePermissionDenied) {
				t.Fatalf("%s error = %v, want permission_denied", query.capability, err)
			}
		})
	}
}

func TestLimitsBoundAggregateInFlightEnvelopeBytes(t *testing.T) {
	t.Parallel()

	limits := provider.DefaultLimits()
	if err := limits.Validate(); err != nil {
		t.Fatalf("DefaultLimits.Validate: %v", err)
	}
	if got, want := limits.MaxInFlightRequests, 64; got != want {
		t.Fatalf("DefaultLimits MaxInFlightRequests = %d, want %d", got, want)
	}

	limits.MaxInFlightRequests++
	if err := limits.Validate(); err == nil {
		t.Fatal("65 in-flight maximum-sized envelopes unexpectedly validated")
	}
}

func TestOversizedResultReturnsStructuredErrorWithoutDisconnect(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "runtime.list_sessions")
	now := time.Now().UTC()
	sessions := make([]protocol.RuntimeSession, 32)
	for index := range sessions {
		sessions[index] = testRuntimeSession(now, protocol.LifecycleRunning)
		sessions[index].NativeSessionID = protocol.NativeID(fmt.Sprintf("native-session-%d", index))
		sessions[index].Extensions = map[string]json.RawMessage{"dev.example.test/data": json.RawMessage(`"` + strings.Repeat("x", 256) + `"`)}
	}
	limits := provider.TestLimits()
	limits.MaxEnvelopeBytes = 4096
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			List: func(context.Context, protocol.RuntimeListSessionsRequest) (protocol.RuntimeListSessionsResult, error) {
				return protocol.RuntimeListSessionsResult{Sessions: sessions}, nil
			},
		}},
	}, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	initialize := testInitializeRequest(manifest)
	initialize.MaximumMessageBytes = limits.MaxEnvelopeBytes
	initialize.MaximumChunkBytes = limits.MaxEnvelopeBytes
	if _, err := client.Initialize(ctx, initialize); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	err = client.Query(ctx, "runtime.list_sessions", protocol.RuntimeListSessionsRequest{}, &protocol.RuntimeListSessionsResult{})
	if !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("runtime.list_sessions error = %v, want message_too_large", err)
	}
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("connection lost after oversized result: %v", err)
	}
}

func TestClientServerLifecycleOverUnixSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket transport")
	}
	t.Parallel()

	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- owner-only directory is required for Unix sockets.
		t.Fatal(err)
	}
	listener, err := provider.ListenUnix(filepath.Join(directory, "provider.sock"))
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close listener: %v", err)
		}
	}()
	manifest := testManifest(t, "provider.initialize", "provider.capabilities")
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serveDone <- acceptErr
			return
		}
		serveDone <- server.ServeConn(ctx, connection)
	}()
	connection, err := provider.DialUnix(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	client, err := provider.NewClient(connection, connection, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := client.Capabilities(ctx); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	select {
	case err := <-serveDone:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ServeConn: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Unix server did not stop")
	}
}

func TestInitializationRejectsIncompatibleNegotiation(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities")
	tests := []struct {
		name   string
		mutate func(*protocol.ProviderInitializeRequest)
		code   protocol.ErrorCode
	}{
		{name: "protocol version", mutate: func(request *protocol.ProviderInitializeRequest) {
			request.SupportedProtocolVersions = []string{"mission-control.provider.v9"}
		}, code: protocol.CodeNotSupported},
		{name: "authentication mode", mutate: func(request *protocol.ProviderInitializeRequest) {
			request.AuthenticationModes = []string{"mtls"}
		}, code: protocol.CodeUnauthenticated},
		{name: "required capability", mutate: func(request *protocol.ProviderInitializeRequest) {
			request.RequiredCapabilities = []protocol.CapabilityName{"runtime.get_session"}
		}, code: protocol.CodeInvalidArgument},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{}, provider.WithLimits(provider.TestLimits()))
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			serverConn, clientConn := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = server.ServeConn(ctx, serverConn) }()
			client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			defer closeProviderClient(t, client)
			request := testInitializeRequest(manifest)
			test.mutate(&request)
			if _, err := client.Initialize(ctx, request); !protocol.IsCode(err, test.code) {
				t.Fatalf("Initialize error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestExpiredCommandDeadlineNeverReachesHandler(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "runtime.create_session")
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			Create: func(context.Context, provider.MutationMeta, protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
				calls.Add(1)
				return protocol.RuntimeSessionResult{}, errors.New("must not run")
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	command := testCommand(t, "expired-command-1", "expired-idempotency-1", "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "native-environment-1", Configuration: json.RawMessage(`{}`), ConfigurationDigest: digest([]byte(`{}`)),
	})
	command.Deadline = time.Now().Add(-time.Second).UTC()
	if err := client.Mutate(ctx, command, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
		t.Fatalf("Mutate error = %v, want deadline_exceeded", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("expired command reached handler %d times", calls.Load())
	}
}

func TestOversizedSubscriptionAcknowledgementRollsBackAdmission(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "events.subscribe")
	limits := provider.TestLimits()
	limits.MaxEnvelopeBytes = 4096
	limits.MaxSubscriptions = 1
	live := make(chan protocol.ProviderEvent)
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Provider: provider.ProviderHandlers{Events: provider.EventHandlers{
			Subscribe: func(context.Context, protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
				if calls.Add(1) == 1 {
					cursors := make([]protocol.EventSubscriptionCursor, 128)
					for index := range cursors {
						cursors[index] = protocol.EventSubscriptionCursor{Role: protocol.RoleSessionRuntime, StreamID: fmt.Sprintf("stream-%d", index)}
					}
					return provider.EventSubscription{
						Result: protocol.EventsSubscribeResult{SubscriptionID: "oversized-sub-1", Cursors: cursors}, Events: live,
					}, nil
				}
				return provider.EventSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: "small-sub-2", Cursors: []protocol.EventSubscriptionCursor{}}, Events: live,
				}, nil
			},
		}},
	}, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	initialize := testInitializeRequest(manifest)
	initialize.MaximumMessageBytes = limits.MaxEnvelopeBytes
	initialize.MaximumChunkBytes = limits.MaxEnvelopeBytes
	if _, err := client.Initialize(ctx, initialize); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	request := protocol.EventsSubscribeRequest{WindowSize: 1}
	if err := client.Query(ctx, "events.subscribe", request, &protocol.EventsSubscribeResult{}); !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("first subscribe error = %v, want message_too_large", err)
	}
	var result protocol.EventsSubscribeResult
	if err := client.Query(ctx, "events.subscribe", request, &result); err != nil {
		t.Fatalf("second subscribe after rollback: %v", err)
	}
	if result.SubscriptionID != "small-sub-2" || calls.Load() != 2 {
		t.Fatalf("second subscription = %#v, calls=%d", result, calls.Load())
	}
}

func TestMutationReservesIdempotencyBudgetBeforeDispatch(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "runtime.create_session")
	limits := provider.TestLimits()
	limits.MaxIdempotencyBytes = limits.MaxEnvelopeBytes + 4096
	now := time.Now().UTC()
	session := testRuntimeSession(now, protocol.LifecycleRunning)
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			Create: func(context.Context, provider.MutationMeta, protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
				if calls.Add(1) == 1 {
					close(firstStarted)
					<-releaseFirst
				}
				return protocol.RuntimeSessionResult{Session: session}, nil
			},
		}},
	}, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(limits))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	request := protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "native-environment-1", Configuration: json.RawMessage(`{}`), ConfigurationDigest: digest([]byte(`{}`)),
	}
	first := testCommand(t, "budget-command-1", "budget-idempotency-1", "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-1", request)
	second := testCommand(t, "budget-command-2", "budget-idempotency-2", "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-2", request)
	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Mutate(ctx, first, &protocol.RuntimeSessionResult{}) }()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first mutation did not reach the handler")
	}
	if err := client.Mutate(ctx, second, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeResourceExhausted) {
		t.Fatalf("second mutation error = %v, want resource_exhausted", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls while budget reserved = %d, want 1", got)
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first mutation: %v", err)
	}
	if err := client.Mutate(ctx, second, &protocol.RuntimeSessionResult{}); err != nil {
		t.Fatalf("second mutation retry: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("handler calls after budget release = %d, want 2", got)
	}
}

func TestInvalidMutationResultIsOutcomeUnknown(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "command.get_result", "runtime.create_session")
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Sessions: provider.RuntimeSessionHandlers{
			Create: func(context.Context, provider.MutationMeta, protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
				calls.Add(1)
				return protocol.RuntimeSessionResult{}, nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ServeConn(ctx, serverConn) }()
	client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer closeProviderClient(t, client)
	if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	command := testCommand(t, "invalid-result-command", "invalid-result-idempotency", "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.RuntimeCreateSessionRequest{
		NativeEnvironmentID: "native-environment-1", Configuration: json.RawMessage(`{}`), ConfigurationDigest: digest([]byte(`{}`)),
	})
	for attempt := 1; attempt <= 2; attempt++ {
		if err := client.Mutate(ctx, command, &protocol.RuntimeSessionResult{}); !protocol.IsCode(err, protocol.CodeOutcomeUnknown) {
			t.Fatalf("attempt %d error = %v, want outcome_unknown", attempt, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls = %d, want 1", got)
	}
	var commandResult protocol.CommandResult
	if err := client.Query(ctx, "command.get_result", protocol.CommandGetResultRequest{CommandID: command.CommandID}, &commandResult); err != nil {
		t.Fatalf("command.get_result: %v", err)
	}
	if commandResult.Status != protocol.CommandResultOutcomeUnknown {
		t.Fatalf("command status = %q, want outcome_unknown", commandResult.Status)
	}
}

func TestTerminalAttachRetryReconcilesOnNewConnection(t *testing.T) {
	t.Parallel()

	manifest := testManifest(t, "provider.initialize", "provider.capabilities", "terminal.attach")
	chunks := make(chan protocol.TerminalChunk)
	var calls atomic.Int32
	server, err := provider.NewServer(provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, provider.HandlerSet{
		Runtime: provider.RuntimeHandlers{Terminal: provider.TerminalHandlers{
			Attach: func(context.Context, provider.MutationMeta, protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
				call := calls.Add(1)
				return provider.TerminalSubscription{
					Result: protocol.EventsSubscribeResult{SubscriptionID: protocol.NativeID(fmt.Sprintf("attach-sub-%d", call)), Cursors: []protocol.EventSubscriptionCursor{}},
					Chunks: chunks,
				}, nil
			},
		}},
	}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	command := testCommand(t, "reconnect-attach-command", "reconnect-attach-idempotency", "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 1024,
	})
	for attempt := 1; attempt <= 2; attempt++ {
		serverConn, clientConn := net.Pipe()
		serveDone := make(chan error, 1)
		ctx, cancel := context.WithCancel(context.Background())
		go func() { serveDone <- server.ServeConn(ctx, serverConn) }()
		client, err := provider.NewClient(clientConn, clientConn, provider.WithLimits(provider.TestLimits()))
		if err != nil {
			cancel()
			t.Fatalf("attempt %d NewClient: %v", attempt, err)
		}
		if _, err := client.Initialize(ctx, testInitializeRequest(manifest)); err != nil {
			_ = client.Close()
			cancel()
			t.Fatalf("attempt %d Initialize: %v", attempt, err)
		}
		var result protocol.EventsSubscribeResult
		if err := client.Mutate(ctx, command, &result); err != nil {
			_ = client.Close()
			cancel()
			t.Fatalf("attempt %d attach: %v", attempt, err)
		}
		if result.SubscriptionID != protocol.NativeID(fmt.Sprintf("attach-sub-%d", attempt)) {
			t.Fatalf("attempt %d subscription = %q", attempt, result.SubscriptionID)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("attempt %d Close: %v", attempt, err)
		}
		cancel()
		select {
		case <-serveDone:
		case <-time.After(time.Second):
			t.Fatalf("attempt %d server did not release connection state", attempt)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("attach handler calls = %d, want 2", got)
	}
}

func testManifest(t *testing.T, names ...protocol.CapabilityName) protocol.ProviderManifest {
	t.Helper()
	capabilities := make([]protocol.CapabilityDescriptor, 0, len(names))
	for _, name := range names {
		capability, ok := protocol.Capability(name)
		if !ok {
			t.Fatalf("unknown test capability %q", name)
		}
		capabilities = append(capabilities, capability)
	}
	return protocol.ProviderManifest{
		ProtocolVersion:     protocol.Version,
		ID:                  "fixture-provider",
		Roles:               []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:                "Fixture Provider",
		Version:             "1.0.0",
		Executable:          "fixture-provider",
		Platforms:           []protocol.Platform{{OS: "linux", Architecture: "amd64"}},
		Capabilities:        capabilities,
		InteractionModes:    []string{"json-rpc"},
		Permissions:         []string{"local-process"},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
}

func testInitializeRequest(manifest protocol.ProviderManifest) protocol.ProviderInitializeRequest {
	return protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.Version},
		GatewayVersion:            "1.0.0",
		Platform:                  manifest.Platforms[0],
		RequiredCapabilities:      []protocol.CapabilityName{"provider.initialize"},
		MaximumMessageBytes:       protocol.MaxMessageBytes,
		MaximumChunkBytes:         protocol.MaxTerminalChunkBytes,
		ReplaySupported:           true,
		AuthenticationModes:       []string{"none"},
		ExperimentalFeatures:      []string{},
	}
}

func testCommand(t *testing.T, commandID, idempotency string, capability protocol.CapabilityName, delivery protocol.DeliveryClass, sessionID string, payload any) protocol.Command {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{
		ProtocolVersion:   protocol.Version,
		CommandID:         commandID,
		SessionID:         sessionID,
		Capability:        capability,
		IdempotencyKey:    idempotency,
		CancellationToken: "stable-cancellation-token",
		Deadline:          time.Now().Add(time.Minute).UTC(),
		DeliveryClass:     delivery,
		Payload:           data,
	}
}

func testRuntimeSession(now time.Time, lifecycle protocol.State) protocol.RuntimeSession {
	return protocol.RuntimeSession{
		ProviderID:      "fixture-provider",
		NativeSessionID: "native-session-1",
		Lifecycle:       testState(now, protocol.AxisLifecycle, lifecycle),
		Health:          testState(now, protocol.AxisHealth, protocol.HealthHealthy),
		Extensions:      map[string]json.RawMessage{},
	}
}

func testState(now time.Time, axis protocol.StateAxis, state protocol.State) protocol.StateReport {
	return protocol.StateReport{
		Axis:       axis,
		State:      state,
		Source:     "fixture",
		ObservedAt: now,
		Sequence:   1,
		Confidence: 1,
		Authority:  protocol.AuthorityAuthoritative,
	}
}

func testOperation(now time.Time, id protocol.NativeID) protocol.OperationResult {
	return protocol.OperationResult{OperationID: id, Status: protocol.OperationSucceeded, ObservedAt: now}
}

func digest(data []byte) protocol.Digest {
	sum := sha256.Sum256(data)
	return protocol.Digest("sha256:" + hex.EncodeToString(sum[:]))
}

func waitNotification(t *testing.T, notifications <-chan provider.Notification, method string, timeout time.Duration) provider.Notification {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case notification, ok := <-notifications:
			if !ok {
				t.Fatalf("notification stream closed while waiting for %s", method)
			}
			if notification.Method == method {
				return notification
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s", method)
		}
	}
}

func closeProviderClient(t *testing.T, client *provider.Client) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Errorf("close provider client: %v", err)
	}
}

func closeConnection(t *testing.T, connection net.Conn) {
	t.Helper()
	if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close connection: %v", err)
	}
}
