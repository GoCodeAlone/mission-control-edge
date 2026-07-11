package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

func TestClientRejectsUnsafeExtensionRequestsAndResults(t *testing.T) {
	const (
		queryCapability    protocol.CapabilityName = "dev.gocodealone.mission-control/query"
		mutationCapability protocol.CapabilityName = "dev.gocodealone.mission-control/mutate"
	)
	descriptors := []protocol.CapabilityDescriptor{
		{Name: queryCapability, Role: protocol.RoleSessionRuntime},
		{Name: mutationCapability, Role: protocol.RoleSessionRuntime, Mutating: true, DeliveryClass: protocol.DeliveryAtMostOnce},
	}

	t.Run("query request", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := client.Query(ctx, queryCapability, json.RawMessage(`{"nested":{"tenant_id":"forged"}}`), new(json.RawMessage))
		if !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("Query unsafe extension request error = %v, want permission_denied", err)
		}
	})

	t.Run("mutation request", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		command := rawTestCommand(t, mutationCapability, protocol.DeliveryAtMostOnce, "", json.RawMessage(`{"nested":{"review_state":"approved"}}`))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := client.Mutate(ctx, command, new(json.RawMessage))
		if !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("Mutate unsafe extension request error = %v, want permission_denied", err)
		}
	})

	t.Run("query result", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		var result json.RawMessage
		done := make(chan error, 1)
		go func() {
			done <- client.Query(context.Background(), queryCapability, json.RawMessage(`{"safe":true}`), &result)
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, json.RawMessage(`{"nested":{"gateway_id":"forged"}}`))
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("Query unsafe extension result error = %v, want permission_denied", err)
		}
	})

	t.Run("mutation result", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		command := rawTestCommand(t, mutationCapability, protocol.DeliveryAtMostOnce, "", json.RawMessage(`{"safe":true}`))
		var result json.RawMessage
		done := make(chan error, 1)
		go func() { done <- client.Mutate(context.Background(), command, &result) }()
		request := peer.readRequest(t)
		peer.respond(t, request, json.RawMessage(`{"nested":{"approved":true}}`))
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("Mutate unsafe extension result error = %v, want permission_denied", err)
		}
	})

	t.Run("custom destination cannot launder result", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		var result launderingExtensionResult
		done := make(chan error, 1)
		go func() {
			done <- client.Query(context.Background(), queryCapability, json.RawMessage(`{"safe":true}`), &result)
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, json.RawMessage(`{"nested":{"gateway_id":"forged"}}`))
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("laundered extension result error = %v, want permission_denied", err)
		}
	})
}

func TestClientSendsTheExactValidatedExtensionRequest(t *testing.T) {
	const capability protocol.CapabilityName = "dev.gocodealone.mission-control/stateful"
	descriptor := protocol.CapabilityDescriptor{Name: capability, Role: protocol.RoleSessionRuntime}
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	requestValue := &statefulExtensionRequest{}
	var result json.RawMessage
	done := make(chan error, 1)
	go func() { done <- client.Query(context.Background(), capability, requestValue, &result) }()
	request := peer.readRequest(t)
	if got := string(request.Params[0]); got != `{"safe":true}` {
		t.Fatalf("wire request = %s, want the validated first encoding", got)
	}
	peer.respond(t, request, json.RawMessage(`{"safe":true}`))
	if err := <-done; err != nil {
		t.Fatalf("Query: %v", err)
	}
	if requestValue.calls != 1 {
		t.Fatalf("MarshalJSON calls = %d, want 1", requestValue.calls)
	}
}

func TestClientRejectsUnsafeRuntimeExtensionsFromRawProvider(t *testing.T) {
	getSession, _ := protocol.Capability("runtime.get_session")
	createSession, _ := protocol.Capability("runtime.create_session")
	descriptors := []protocol.CapabilityDescriptor{getSession, createSession}

	t.Run("query result", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		var result protocol.RuntimeSessionResult
		done := make(chan error, 1)
		go func() {
			done <- client.Query(context.Background(), "runtime.get_session", protocol.RuntimeSessionRequest{NativeSessionID: "native-session-1"}, &result)
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, unsafeRawRuntimeResult())
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("unsafe runtime query result error = %v, want permission_denied", err)
		}
	})

	t.Run("mutation result", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		configuration := json.RawMessage(`{}`)
		command := rawTestCommand(t, "runtime.create_session", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.RuntimeCreateSessionRequest{
			NativeEnvironmentID: "native-environment-1",
			Configuration:       configuration,
			ConfigurationDigest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		})
		var result protocol.RuntimeSessionResult
		done := make(chan error, 1)
		go func() { done <- client.Mutate(context.Background(), command, &result) }()
		request := peer.readRequest(t)
		peer.respond(t, request, unsafeRawRuntimeResult())
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("unsafe runtime mutation result error = %v, want permission_denied", err)
		}
	})

	t.Run("raw destination", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptors...)
		defer closeRawProviderClient(t, client, peer)
		var result json.RawMessage
		done := make(chan error, 1)
		go func() {
			done <- client.Query(context.Background(), "runtime.get_session", protocol.RuntimeSessionRequest{NativeSessionID: "native-session-1"}, &result)
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, unsafeRawRuntimeResult())
		if err := <-done; !protocol.IsCode(err, protocol.CodePermissionDenied) {
			t.Fatalf("unsafe raw runtime result error = %v, want permission_denied", err)
		}
	})
}

func TestClientValidatesCanonicalCoreBytesIndependentOfCallerTypes(t *testing.T) {
	health, _ := protocol.Capability("provider.health")

	t.Run("custom request marshaler", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, health)
		defer closeRawProviderClient(t, client, peer)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		err := client.Query(ctx, "provider.health", invalidCoreRequest{}, &protocol.ProviderHealthResult{})
		if !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Fatalf("invalid custom core request error = %v, want invalid_argument", err)
		}
	})

	t.Run("custom result unmarshaler", func(t *testing.T) {
		client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, health)
		defer closeRawProviderClient(t, client, peer)
		var result launderingCoreResult
		done := make(chan error, 1)
		go func() {
			done <- client.Query(context.Background(), "provider.health", protocol.ProviderHealthRequest{}, &result)
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, json.RawMessage(`{}`))
		if err := <-done; !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Fatalf("laundered core result error = %v, want invalid_argument", err)
		}
	})
}

func TestEveryCoreCapabilityHasCanonicalClientCodecs(t *testing.T) {
	for _, descriptor := range protocol.KnownCapabilities() {
		codec, ok := clientCapabilityCodecFor(descriptor.Name)
		if !ok {
			t.Errorf("capability %q has no canonical client codec", descriptor.Name)
			continue
		}
		if codec.request == nil {
			t.Errorf("capability %q has no canonical request validator", descriptor.Name)
		}
		if codec.result == nil {
			t.Errorf("capability %q has no canonical result validator", descriptor.Name)
		}
	}
}

func TestClientClosesTransportAfterAmbiguousStreamingQueryCancellation(t *testing.T) {
	events, _ := protocol.Capability("events.subscribe")
	topology, _ := protocol.Capability("topology.subscribe")
	tests := []struct {
		name       string
		descriptor protocol.CapabilityDescriptor
		request    any
	}{
		{
			name:       "events subscribe",
			descriptor: events,
			request: protocol.EventsSubscribeRequest{
				Cursors:    []protocol.EventSubscriptionCursor{},
				WindowSize: 1,
			},
		},
		{
			name:       "topology subscribe",
			descriptor: topology,
			request:    protocol.WorkspaceRequest{NativeWorkspaceID: "native-workspace-1"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, test.descriptor)
			defer closeRawProviderClient(t, client, peer)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- client.Query(ctx, test.descriptor.Name, test.request, &protocol.EventsSubscribeResult{})
			}()
			request := peer.readRequest(t)
			if request.Method != string(test.descriptor.Name) {
				t.Fatalf("method = %q, want %q", request.Method, test.descriptor.Name)
			}
			if err := <-done; !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
				t.Fatalf("streaming query timeout error = %v, want deadline_exceeded", err)
			}
			select {
			case <-client.done:
			case <-time.After(time.Second):
				t.Fatal("ambiguous streaming query left client transport open")
			}
		})
	}
}

func TestClientEnforcesNegotiatedTerminalInputLimitBeforeWrite(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.send_input")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	command := rawTestCommand(t, "terminal.send_input", protocol.DeliveryAtMostOnce, "canonical-session-1", protocol.TerminalInputRequest{
		NativeSessionID: "native-session-1",
		StreamID:        "stdout",
		Encoding:        protocol.TerminalEncodingUTF8,
		Data:            "12345",
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := client.Mutate(ctx, command, &protocol.OperationResult{}); !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("terminal.send_input error = %v, want message_too_large", err)
	}
}

func TestClientTerminalSubscriptionRejectsDuplicateStream(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	client, peer := newRawProviderClient(t, protocol.MaxTerminalChunkBytes, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	request := protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4}
	subscribeRawTerminal(t, client, peer, request)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.SubscribeTerminal(ctx, request); !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("duplicate terminal subscription error = %v, want conflict", err)
	}
}

func TestClientTerminalFlowReservationsAreBounded(t *testing.T) {
	first := protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4}
	second := protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-2", StreamID: "stdout", WindowBytes: 4}

	t.Run("direct subscription", func(t *testing.T) {
		client := &Client{limits: Limits{MaxSubscriptions: 1}, terminalFlows: make(map[terminalStreamKey]*clientTerminalFlow)}
		if _, err := client.reserveTerminalFlow(first); err != nil {
			t.Fatalf("first reservation: %v", err)
		}
		if _, err := client.reserveTerminalFlow(second); !protocol.IsCode(err, protocol.CodeResourceExhausted) {
			t.Fatalf("second reservation error = %v, want resource_exhausted", err)
		}
	})

	t.Run("attached subscription", func(t *testing.T) {
		client := &Client{limits: Limits{MaxSubscriptions: 1}, terminalFlows: make(map[terminalStreamKey]*clientTerminalFlow)}
		if _, err := client.reserveTerminalFlow(first); err != nil {
			t.Fatalf("first reservation: %v", err)
		}
		command := rawTestCommand(t, "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", second)
		if _, err := client.reserveAttachedTerminalFlow(second, command); !protocol.IsCode(err, protocol.CodeResourceExhausted) {
			t.Fatalf("attached reservation error = %v, want resource_exhausted", err)
		}
	})
}

func TestClientSubscribeTimeoutClosesUncertainTransport(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.SubscribeTerminal(ctx, protocol.TerminalSubscribeRequest{
			NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
		})
		done <- err
	}()
	request := peer.readRequest(t)
	if request.Method != "terminal.subscribe" {
		t.Fatalf("method = %q, want terminal.subscribe", request.Method)
	}
	if err := <-done; !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
		t.Fatalf("SubscribeTerminal timeout error = %v, want deadline_exceeded", err)
	}
	select {
	case <-client.done:
	case <-time.After(time.Second):
		t.Fatal("uncertain terminal subscription left client transport open")
	}
}

func TestClosedTerminalFlowRejectsLateCredit(t *testing.T) {
	flow := newClientTerminalFlow(protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	})
	flow.remaining = 2
	flow.throughOffset = 2
	flow.close()
	client := &Client{
		initialized: true,
		maximum:     TestLimits().MaxEnvelopeBytes,
		limits:      TestLimits(),
		terminalFlows: map[terminalStreamKey]*clientTerminalFlow{
			{nativeSession: "native-session-1", streamID: "stdout"}: flow,
		},
	}
	err := client.SendTerminalCredit(context.Background(), protocol.TerminalCredit{
		NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 1, ThroughOffset: 2,
	})
	if !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("late terminal credit error = %v, want conflict", err)
	}
}

func TestRetiringTerminalFlowRejectsPreviouslyFetchedCredit(t *testing.T) {
	flow := newClientTerminalFlow(protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	})
	flow.remaining = 2
	flow.throughOffset = 2
	key := terminalStreamKey{nativeSession: "native-session-1", streamID: "stdout"}
	client := &Client{
		initialized:   true,
		maximum:       TestLimits().MaxEnvelopeBytes,
		limits:        TestLimits(),
		terminalFlows: map[terminalStreamKey]*clientTerminalFlow{key: flow},
	}
	previouslyFetched := client.terminalFlow("native-session-1", "stdout")
	client.mu.Lock()
	flow.retiring = true
	client.mu.Unlock()
	err := client.sendTerminalCredit(context.Background(), protocol.TerminalCredit{
		NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 1, ThroughOffset: 2,
	}, previouslyFetched)
	if !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("retiring terminal credit error = %v, want conflict", err)
	}
}

func TestClientDirectTerminalSubscribeQueryTracksFlow(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	request := protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4}
	var result protocol.EventsSubscribeResult
	done := make(chan error, 1)
	go func() { done <- client.Query(context.Background(), "terminal.subscribe", request, &result) }()
	rpcRequest := peer.readRequest(t)
	peer.respond(t, rpcRequest, protocol.EventsSubscribeResult{SubscriptionID: "raw-direct-subscription", Cursors: []protocol.EventSubscriptionCursor{}})
	if err := <-done; err != nil {
		t.Fatalf("direct terminal.subscribe query: %v", err)
	}
	peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(1, 0, "a", 3, false))
	waitRawNotification(t, client, NotificationTerminalChunk)
}

func TestClientTracksTerminalAttachAndAllowsSameCommandRetry(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.attach")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	attachRequest := protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	}
	command := rawTestCommand(t, "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", attachRequest)

	attach := func(command protocol.Command) error {
		done := make(chan error, 1)
		go func() { done <- client.Mutate(context.Background(), command, &protocol.EventsSubscribeResult{}) }()
		request := peer.readRequest(t)
		peer.respond(t, request, protocol.EventsSubscribeResult{SubscriptionID: "raw-attach-subscription", Cursors: []protocol.EventSubscriptionCursor{}})
		return <-done
	}
	if err := attach(command); err != nil {
		t.Fatalf("initial terminal.attach: %v", err)
	}
	peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(1, 0, "a", 3, false))
	waitRawNotification(t, client, NotificationTerminalChunk)
	if err := attach(command); err != nil {
		t.Fatalf("same-command terminal.attach retry: %v", err)
	}

	different := command
	different.CommandID = "client-command-2"
	different.IdempotencyKey = "client-idempotency-2"
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := client.Mutate(ctx, different, &protocol.EventsSubscribeResult{}); !protocol.IsCode(err, protocol.CodeConflict) {
		t.Fatalf("different terminal.attach on active stream error = %v, want conflict", err)
	}
}

func TestClientCanceledAttachDoesNotReserveFlow(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.attach")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	command := rawTestCommand(t, "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Mutate(ctx, command, &protocol.EventsSubscribeResult{}); !protocol.IsCode(err, protocol.CodeCancelled) {
		t.Fatalf("canceled attach error = %v, want cancelled", err)
	}
	client.mu.Lock()
	flows := len(client.terminalFlows)
	client.mu.Unlock()
	if flows != 0 {
		t.Fatalf("terminal flows after pre-canceled attach = %d, want 0", flows)
	}
}

func TestClientDistinguishesMalformedAndRemoteSubscriptionErrors(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	requestValue := protocol.TerminalSubscribeRequest{NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4}

	t.Run("malformed acknowledgement closes", func(t *testing.T) {
		client, peer := newRawProviderClient(t, 4, true, descriptor)
		defer closeRawProviderClient(t, client, peer)
		done := make(chan error, 1)
		go func() {
			_, err := client.SubscribeTerminal(context.Background(), requestValue)
			done <- err
		}()
		request := peer.readRequest(t)
		peer.respond(t, request, json.RawMessage(`{}`))
		if err := <-done; !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Fatalf("malformed acknowledgement error = %v, want invalid_argument", err)
		}
		select {
		case <-client.done:
		case <-time.After(time.Second):
			t.Fatal("malformed subscription acknowledgement left transport open")
		}
	})

	t.Run("remote rejection stays connected", func(t *testing.T) {
		client, peer := newRawProviderClient(t, 4, true, descriptor)
		defer closeRawProviderClient(t, client, peer)
		done := make(chan error, 1)
		go func() {
			_, err := client.SubscribeTerminal(context.Background(), requestValue)
			done <- err
		}()
		request := peer.readRequest(t)
		peer.respondError(t, request, newProtocolError(protocol.CodeInvalidArgument))
		if err := <-done; !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Fatalf("remote rejection error = %v, want invalid_argument", err)
		}
		select {
		case <-client.done:
			t.Fatal("remote subscription rejection closed healthy transport")
		default:
		}
	})
}

func TestClientConcurrentTerminalAttachRetryKeepsSharedFlow(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.attach")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	command := rawTestCommand(t, "terminal.attach", protocol.DeliveryStateReconciled, "canonical-session-1", protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	})
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	firstDone := make(chan error, 1)
	go func() { firstDone <- client.Mutate(firstContext, command, &protocol.EventsSubscribeResult{}) }()
	firstRequest := peer.readRequest(t)
	if firstRequest.Method != "terminal.attach" {
		t.Fatalf("first method = %q, want terminal.attach", firstRequest.Method)
	}
	secondDone := make(chan error, 1)
	go func() { secondDone <- client.Mutate(context.Background(), command, &protocol.EventsSubscribeResult{}) }()
	secondRequest := peer.readRequest(t)
	if secondRequest.Method != "terminal.attach" {
		t.Fatalf("second method = %q, want terminal.attach", secondRequest.Method)
	}
	cancelFirst()
	if err := <-firstDone; !protocol.IsCode(err, protocol.CodeCancelled) {
		t.Fatalf("first attach error = %v, want cancelled", err)
	}
	cancelRequest := peer.readRequest(t)
	if cancelRequest.Method != NotificationCancel {
		t.Fatalf("post-timeout method = %q, want %q", cancelRequest.Method, NotificationCancel)
	}
	peer.respond(t, secondRequest, protocol.EventsSubscribeResult{SubscriptionID: "raw-concurrent-attach", Cursors: []protocol.EventSubscriptionCursor{}})
	if err := <-secondDone; err != nil {
		t.Fatalf("concurrent attach retry: %v", err)
	}
	peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(1, 0, "a", 3, false))
	waitRawNotification(t, client, NotificationTerminalChunk)
}

func TestClientReplayChecksCanonicalRequestContent(t *testing.T) {
	read, _ := protocol.Capability("terminal.read")
	events, _ := protocol.Capability("events.subscribe")
	tests := []struct {
		name       string
		capability protocol.CapabilityName
		request    any
		result     any
	}{
		{
			name: "terminal read", capability: "terminal.read",
			request: &protocol.TerminalReadRequest{NativeSessionID: "native-session-1", StreamID: "stdout", AfterOffset: 1, MaximumBytes: 1},
			result:  &protocol.TerminalChunk{},
		},
		{
			name: "event subscription", capability: "events.subscribe",
			request: &protocol.EventsSubscribeRequest{Cursors: []protocol.EventSubscriptionCursor{{Role: protocol.RoleSessionRuntime, StreamID: "runtime-events", AfterSequence: 1}}, WindowSize: 1},
			result:  &protocol.EventsSubscribeResult{},
		},
		{
			name: "raw terminal read", capability: "terminal.read",
			request: json.RawMessage(`{"native_session_id":"native-session-1","stream_id":"stdout","after_offset":1,"maximum_bytes":1}`),
			result:  &protocol.TerminalChunk{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newRawProviderClient(t, 4, false, read, events)
			defer closeRawProviderClient(t, client, peer)
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if err := client.Query(ctx, test.capability, test.request, test.result); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
				t.Fatalf("pointer replay request error = %v, want invalid_argument", err)
			}
		})
	}
}

func TestClientBindsTerminalReadResultToRequest(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.read")
	tests := []struct {
		name  string
		chunk protocol.TerminalChunk
	}{
		{name: "native session", chunk: func() protocol.TerminalChunk {
			value := rawTerminalChunk(1, 0, "a", 0, false)
			value.NativeSessionID = "other-session"
			return value
		}()},
		{name: "stream", chunk: func() protocol.TerminalChunk {
			value := rawTerminalChunk(1, 0, "a", 0, false)
			value.StreamID = "stderr"
			return value
		}()},
		{name: "offset", chunk: rawTerminalChunk(1, 1, "a", 0, false)},
		{name: "requested bytes", chunk: rawTerminalChunk(1, 0, "abc", 0, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newRawProviderClient(t, 4, true, descriptor)
			defer closeRawProviderClient(t, client, peer)
			var result protocol.TerminalChunk
			done := make(chan error, 1)
			go func() {
				done <- client.Query(context.Background(), "terminal.read", protocol.TerminalReadRequest{
					NativeSessionID: "native-session-1", StreamID: "stdout", MaximumBytes: 2,
				}, &result)
			}()
			request := peer.readRequest(t)
			peer.respond(t, request, test.chunk)
			if err := <-done; !protocol.IsCode(err, protocol.CodeInvalidArgument) && !protocol.IsCode(err, protocol.CodeSequenceConflict) && !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
				t.Fatalf("terminal.read binding error = %v, want request-binding rejection", err)
			}
		})
	}
}

func TestClientValidatesTerminalSubscriptionChunks(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	tests := []struct {
		name     string
		maximum  uint64
		replay   bool
		window   uint64
		first    *protocol.TerminalChunk
		chunk    protocol.TerminalChunk
		wantCode protocol.ErrorCode
	}{
		{
			name: "replay not negotiated", maximum: 4, replay: false, window: 4,
			chunk: rawTerminalChunk(1, 0, "a", 3, true), wantCode: protocol.CodeInvalidArgument,
		},
		{
			name: "offset conflict", maximum: 4, replay: true, window: 4,
			chunk: rawTerminalChunk(1, 1, "a", 3, false), wantCode: protocol.CodeSequenceConflict,
		},
		{
			name: "sequence conflict", maximum: 4, replay: true, window: 4,
			first: chunkPointer(rawTerminalChunk(1, 0, "a", 3, false)),
			chunk: rawTerminalChunk(3, 1, "b", 2, false), wantCode: protocol.CodeSequenceConflict,
		},
		{
			name: "forged remaining credit", maximum: 4, replay: true, window: 4,
			chunk: rawTerminalChunk(1, 0, "a", 4, false), wantCode: protocol.CodeInvalidArgument,
		},
		{
			name: "negotiated chunk overflow", maximum: 4, replay: true, window: 8,
			chunk: rawTerminalChunk(1, 0, "12345", 3, false), wantCode: protocol.CodeMessageTooLarge,
		},
		{
			name: "window overflow", maximum: 8, replay: true, window: 4,
			chunk: rawTerminalChunk(1, 0, "12345", 0, false), wantCode: protocol.CodeInvalidArgument,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, peer := newRawProviderClient(t, test.maximum, test.replay, descriptor)
			defer closeRawProviderClient(t, client, peer)
			subscribeRawTerminal(t, client, peer, protocol.TerminalSubscribeRequest{
				NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: test.window,
			})
			if test.first != nil {
				peer.notify(t, NotificationTerminalChunk, *test.first)
				waitRawNotification(t, client, NotificationTerminalChunk)
			}
			peer.notify(t, NotificationTerminalChunk, test.chunk)
			waitClientFailure(t, client, test.wantCode)
		})
	}
}

func TestClientTerminalCreditUpdatesLocalWindow(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	client, peer := newRawProviderClient(t, 4, true, descriptor)
	defer closeRawProviderClient(t, client, peer)
	subscribeRawTerminal(t, client, peer, protocol.TerminalSubscribeRequest{
		NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
	})
	peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(1, 0, "ab", 2, false))
	waitRawNotification(t, client, NotificationTerminalChunk)

	creditDone := make(chan error, 1)
	go func() {
		creditDone <- client.SendTerminalCredit(context.Background(), protocol.TerminalCredit{
			NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 2, ThroughOffset: 2,
		})
	}()
	credit := peer.readRequest(t)
	if credit.Method != NotificationTerminalCredit || !credit.isNotification() {
		t.Fatalf("credit frame = %#v, want %s notification", credit, NotificationTerminalCredit)
	}
	if err := <-creditDone; err != nil {
		t.Fatalf("SendTerminalCredit: %v", err)
	}
	peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(2, 2, "cde", 1, false))
	waitRawNotification(t, client, NotificationTerminalChunk)
}

func TestClientRejectsInvalidTerminalCreditBeforeWrite(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.subscribe")
	tests := []protocol.TerminalCredit{
		{NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 1, ThroughOffset: 1},
		{NativeSessionID: "native-session-1", StreamID: "stdout", Bytes: 3, ThroughOffset: 2},
	}
	for _, credit := range tests {
		client, peer := newRawProviderClient(t, 4, true, descriptor)
		subscribeRawTerminal(t, client, peer, protocol.TerminalSubscribeRequest{
			NativeSessionID: "native-session-1", StreamID: "stdout", WindowBytes: 4,
		})
		peer.notify(t, NotificationTerminalChunk, rawTerminalChunk(1, 0, "ab", 2, false))
		waitRawNotification(t, client, NotificationTerminalChunk)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := client.SendTerminalCredit(ctx, credit)
		cancel()
		if !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Errorf("SendTerminalCredit(%#v) error = %v, want invalid_argument", credit, err)
		}
		closeRawProviderClient(t, client, peer)
	}
}

func TestClientRejectsReplayedTerminalReadWhenReplayWasNotNegotiated(t *testing.T) {
	descriptor, _ := protocol.Capability("terminal.read")
	client, peer := newRawProviderClient(t, 4, false, descriptor)
	defer closeRawProviderClient(t, client, peer)
	var result protocol.TerminalChunk
	done := make(chan error, 1)
	go func() {
		done <- client.Query(context.Background(), "terminal.read", protocol.TerminalReadRequest{
			NativeSessionID: "native-session-1", StreamID: "stdout", MaximumBytes: 4,
		}, &result)
	}()
	request := peer.readRequest(t)
	peer.respond(t, request, rawTerminalChunk(1, 0, "a", 0, true))
	if err := <-done; !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("replayed terminal.read error = %v, want invalid_argument", err)
	}
}

func TestReadFrameEnforcesLimitAndLineEnding(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", 33) + "\n"))
	if _, err := readFrame(reader, 32); !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("oversize error = %v, want message_too_large", err)
	}
	reader = bufio.NewReader(strings.NewReader("{}\r\n"))
	if _, err := readFrame(reader, 32); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("CRLF error = %v, want invalid_argument", err)
	}
	reader = bufio.NewReader(strings.NewReader("\n"))
	if _, err := readFrame(reader, 32); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("empty-frame error = %v, want invalid_argument", err)
	}
}

func TestWriteFrameAppendsOneLF(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := writeFrame(&output, []byte(`{"jsonrpc":"2.0"}`), 128); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if got, want := output.String(), "{\"jsonrpc\":\"2.0\"}\n"; got != want {
		t.Fatalf("frame = %q, want %q", got, want)
	}
}

func TestDecodeRPCRejectsUnknownFieldsAndNonStringIDs(t *testing.T) {
	t.Parallel()

	cases := []string{
		`{"jsonrpc":"2.0","id":"request-1","method":"provider.health","params":[{}],"extra":true}`,
		`{"jsonrpc":"2.0","id":7,"method":"provider.health","params":[{}]}`,
		`{"jsonrpc":"2.0","id":"request-1","method":"provider.health","params":{}}`,
		`{"jsonrpc":"2.0","id":"request-1","method":"provider.health","params":[{},{}]}`,
	}
	for _, input := range cases {
		if _, err := decodeRPCRequest([]byte(input), 4096); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
			t.Fatalf("decodeRPCRequest(%s) error = %v, want invalid_argument", input, err)
		}
	}
	response := `{"jsonrpc":"2.0","id":"request-1","result":{},"extra":true}`
	if _, err := decodeRPCResponse([]byte(response), 4096); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("decodeRPCResponse error = %v, want invalid_argument", err)
	}
	notification, err := decodeRPCRequest([]byte(`{"jsonrpc":"2.0","method":"$mc/cancel","params":[{"request_id":"request-1","extra":true}]}`), 4096)
	if err != nil {
		t.Fatalf("decode notification envelope: %v", err)
	}
	if err := decodeRPCParam(notification, &CancelRequest{}); !protocol.IsCode(err, protocol.CodeInvalidArgument) {
		t.Fatalf("decode notification param error = %v, want invalid_argument", err)
	}
}

func TestOutboundDataQueueAppliesBackpressure(t *testing.T) {
	t.Parallel()

	connection := &serverConnection{
		ctx:  context.Background(),
		data: make(chan outboundFrame, 1),
	}
	if err := connection.enqueueData(outboundFrame{data: []byte(`{}`)}); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if err := connection.enqueueData(outboundFrame{data: []byte(`{}`)}); !protocol.IsCode(err, protocol.CodeResourceExhausted) {
		t.Fatalf("second enqueue error = %v, want resource_exhausted", err)
	}
}

func TestHeartbeatCoalescesWhenDataQueueIsFull(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connection := &serverConnection{
		ctx:     ctx,
		cancel:  cancel,
		maximum: 4096,
		data:    make(chan outboundFrame, 1),
	}
	connection.data <- outboundFrame{data: []byte(`{}`)}
	if err := connection.sendHeartbeat(time.Now().UTC()); err != nil {
		t.Fatalf("sendHeartbeat on full queue: %v", err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("heartbeat backpressure canceled the connection")
	default:
	}
}

func TestCommandDeadlineRollsBackWhileControlQueueIsFull(t *testing.T) {
	t.Parallel()

	capabilityNames := []protocol.CapabilityName{"provider.initialize", "provider.capabilities", "provider.shutdown", "command.get_result"}
	capabilities := make([]protocol.CapabilityDescriptor, 0, len(capabilityNames))
	for _, name := range capabilityNames {
		descriptor, ok := protocol.Capability(name)
		if !ok {
			t.Fatalf("missing capability %q", name)
		}
		capabilities = append(capabilities, descriptor)
	}
	manifest := protocol.ProviderManifest{
		ProtocolVersion: protocol.Version,
		ID:              "deadline-provider",
		Roles:           []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:            "Deadline Provider",
		Version:         "1.0.0",
		Executable:      "deadline-provider",
		Platforms:       []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities:    capabilities,
		InteractionModes: []string{
			"json-rpc",
		},
		Permissions:         []string{},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
	handlerCalls := 0
	server, err := NewServer(ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}}, HandlerSet{
		Provider: ProviderHandlers{Shutdown: func(context.Context, MutationMeta, protocol.ProviderShutdownRequest) (protocol.OperationResult, error) {
			handlerCalls++
			return protocol.OperationResult{OperationID: "deadline-shutdown", Status: protocol.OperationSucceeded, ObservedAt: time.Now().UTC()}, nil
		}},
	}, WithLimits(TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	connectionCtx, cancelConnection := context.WithCancel(context.Background())
	defer cancelConnection()
	connection := &serverConnection{
		server:              server,
		id:                  "deadline-connection",
		ctx:                 connectionCtx,
		cancel:              cancelConnection,
		initialized:         true,
		maximum:             TestLimits().MaxEnvelopeBytes,
		maximumChunk:        uint64(protocol.MaxTerminalChunkBytes),
		active:              make(map[string]context.CancelFunc),
		subscriptionCancels: make(map[protocol.NativeID]*subscriptionAdmission),
		terminalStreams:     make(map[string]*subscriptionAdmission),
		control:             make(chan outboundFrame, 1),
		data:                make(chan outboundFrame, 1),
	}
	connection.control <- outboundFrame{data: []byte(`{}`)}
	command := rawTestCommand(t, "provider.shutdown", protocol.DeliveryProviderIdempotent, "", protocol.ProviderShutdownRequest{})
	command.Deadline = time.Now().Add(40 * time.Millisecond).UTC()
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancelRequest := context.WithCancel(connectionCtx)
	connection.active["deadline-request"] = cancelRequest
	started := time.Now()
	connection.processRequest(requestCtx, cancelRequest, raw, rpcRequest{JSONRPC: jsonRPCVersion, ID: "deadline-request", Method: "provider.shutdown", Params: []json.RawMessage{raw}})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("deadline rollback took %s", elapsed)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler calls = %d, want 1", handlerCalls)
	}
	result, err := server.commandResult(command.CommandID)
	if err != nil {
		t.Fatalf("commandResult: %v", err)
	}
	if result.Status != protocol.CommandResultOutcomeUnknown {
		t.Fatalf("command result = %q, want outcome_unknown", result.Status)
	}
	select {
	case <-connectionCtx.Done():
		t.Fatal("deadline rollback shut down the connection without committing provider.shutdown")
	default:
	}
}

func TestLimitsBoundWorstCaseOutboundBytes(t *testing.T) {
	t.Parallel()

	limits := DefaultLimits()
	limits.MaxEnvelopeBytes = protocol.MaxMessageBytes
	limits.MaxOutboundQueue = 65
	if err := limits.Validate(); err == nil {
		t.Fatal("Limits accepted more than 256 MiB of worst-case queued frames")
	}
}

func TestUnixSocketPermissionsDialAndInodeSafeCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket behavior")
	}
	t.Parallel()

	directory := resolvedTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- owner-only directory is required for Unix sockets.
		t.Fatal(err)
	}
	path := filepath.Join(directory, "provider.sock")
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatalf("ListenUnix: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode = %#o, want 0600", got)
	}

	accepted := make(chan net.Conn, 1)
	acceptErrors := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptErrors <- acceptErr
			return
		}
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client, err := DialUnix(ctx, path)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	_ = client.Close()
	select {
	case server := <-accepted:
		_ = server.Close()
	case err := <-acceptErrors:
		t.Fatalf("Accept: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out accepting Unix connection")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "replacement" { // #nosec G304 -- path is inside this test's t.TempDir.
		t.Fatalf("replacement after close = %q, %v", data, err)
	}
}

func TestUnixSocketRejectsUnsafeParentAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket behavior")
	}
	t.Parallel()

	unsafe := t.TempDir()
	if err := os.Chmod(unsafe, 0o755); err != nil { // #nosec G302 -- intentionally unsafe mode is the negative-test input.
		t.Fatal(err)
	}
	if listener, err := ListenUnix(filepath.Join(unsafe, "provider.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("ListenUnix accepted a group/world-readable parent")
	}

	realParent := t.TempDir()
	if err := os.Chmod(realParent, 0o700); err != nil { // #nosec G302 -- owner-only directory is required for Unix sockets.
		t.Fatal(err)
	}
	linkRoot := t.TempDir()
	link := filepath.Join(linkRoot, "linked")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	if listener, err := ListenUnix(filepath.Join(link, "provider.sock")); err == nil {
		_ = listener.Close()
		t.Fatal("ListenUnix accepted a symlinked parent")
	}
}

func TestDialUnixRejectsRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket behavior")
	}
	t.Parallel()

	directory := resolvedTempDir(t)
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- owner-only directory is required for Unix sockets.
		t.Fatal(err)
	}
	path := filepath.Join(directory, "provider.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	connection, err := DialUnix(context.Background(), path)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("DialUnix regular-file error = %v", err)
	}
}

func resolvedTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

type rawProviderPeer struct {
	connection net.Conn
	reader     *bufio.Reader
	maximum    uint64
}

type launderingExtensionResult struct{}

func (*launderingExtensionResult) UnmarshalJSON([]byte) error { return nil }

func (launderingExtensionResult) MarshalJSON() ([]byte, error) {
	return []byte(`{"safe":true}`), nil
}

type invalidCoreRequest struct{}

func (invalidCoreRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"unexpected":true}`), nil
}

type launderingCoreResult struct{}

func (*launderingCoreResult) UnmarshalJSON([]byte) error { return nil }

type statefulExtensionRequest struct{ calls int }

func (r *statefulExtensionRequest) MarshalJSON() ([]byte, error) {
	r.calls++
	if r.calls == 1 {
		return []byte(`{"safe":true}`), nil
	}
	return []byte(`{"nested":{"tenant_id":"forged"}}`), nil
}

func newRawProviderClient(t *testing.T, maximumChunk uint64, replay bool, descriptors ...protocol.CapabilityDescriptor) (*Client, *rawProviderPeer) {
	t.Helper()
	initialize, _ := protocol.Capability("provider.initialize")
	manifest := protocol.ProviderManifest{
		ProtocolVersion: protocol.Version,
		ID:              "raw-provider",
		Roles:           []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:            "Raw Provider",
		Version:         "1.0.0",
		Executable:      "raw-provider",
		Platforms:       []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities:    append([]protocol.CapabilityDescriptor{initialize}, descriptors...),
		InteractionModes: []string{
			"json-rpc",
		},
		Permissions:         []string{},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
	limits := TestLimits()
	if maximumChunk > limits.MaxEnvelopeBytes {
		maximumChunk = limits.MaxEnvelopeBytes
	}
	providerConnection, clientConnection := net.Pipe()
	peer := &rawProviderPeer{connection: providerConnection, reader: bufio.NewReaderSize(providerConnection, 64<<10), maximum: limits.MaxEnvelopeBytes}
	client, err := NewClient(clientConnection, clientConnection, WithLimits(limits))
	if err != nil {
		_ = providerConnection.Close()
		_ = clientConnection.Close()
		t.Fatalf("NewClient: %v", err)
	}
	providerDone := make(chan error, 1)
	go func() {
		request, readErr := peer.readRequestValue()
		if readErr != nil {
			providerDone <- readErr
			return
		}
		if request.Method != "provider.initialize" {
			providerDone <- newProtocolError(protocol.CodeInvalidArgument)
			return
		}
		response, marshalErr := marshalResponse(request.ID, protocol.ProviderInitializeResult{
			ProtocolVersion:      protocol.Version,
			Manifest:             manifest,
			NativeRuntimeVersion: "1.0.0",
			MaximumMessageBytes:  limits.MaxEnvelopeBytes,
			MaximumChunkBytes:    maximumChunk,
			ReplaySupported:      replay,
			AuthenticationMode:   "none",
			ExperimentalFeatures: []string{},
		}, limits.MaxEnvelopeBytes)
		if marshalErr != nil {
			providerDone <- marshalErr
			return
		}
		providerDone <- writeFrame(providerConnection, response, limits.MaxEnvelopeBytes)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Initialize(ctx, protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.Version},
		GatewayVersion:            "1.0.0",
		Platform:                  manifest.Platforms[0],
		RequiredCapabilities:      []protocol.CapabilityName{"provider.initialize"},
		MaximumMessageBytes:       limits.MaxEnvelopeBytes,
		MaximumChunkBytes:         maximumChunk,
		ReplaySupported:           replay,
		AuthenticationModes:       []string{"none"},
		ExperimentalFeatures:      []string{},
	})
	if providerErr := <-providerDone; providerErr != nil {
		_ = client.Close()
		_ = providerConnection.Close()
		t.Fatalf("raw provider initialize response: %v", providerErr)
	}
	if err != nil {
		_ = client.Close()
		_ = providerConnection.Close()
		t.Fatalf("Initialize: %v", err)
	}
	return client, peer
}

func (p *rawProviderPeer) readRequestValue() (rpcRequest, error) {
	if err := p.connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return rpcRequest{}, err
	}
	defer func() { _ = p.connection.SetReadDeadline(time.Time{}) }()
	frame, err := readFrame(p.reader, p.maximum)
	if err != nil {
		return rpcRequest{}, err
	}
	return decodeRPCRequest(frame, p.maximum)
}

func (p *rawProviderPeer) readRequest(t *testing.T) rpcRequest {
	t.Helper()
	request, err := p.readRequestValue()
	if err != nil {
		t.Fatalf("read raw provider request: %v", err)
	}
	return request
}

func (p *rawProviderPeer) respond(t *testing.T, request rpcRequest, result any) {
	t.Helper()
	frame, err := marshalResponse(request.ID, result, p.maximum)
	if err != nil {
		t.Fatalf("marshal raw provider response: %v", err)
	}
	p.write(t, frame)
}

func (p *rawProviderPeer) respondError(t *testing.T, request rpcRequest, result error) {
	t.Helper()
	frame, err := marshalErrorResponse(request.ID, result, p.maximum)
	if err != nil {
		t.Fatalf("marshal raw provider error response: %v", err)
	}
	p.write(t, frame)
}

func (p *rawProviderPeer) notify(t *testing.T, method string, value any) {
	t.Helper()
	frame, err := marshalNotification(method, value, p.maximum)
	if err != nil {
		t.Fatalf("marshal raw provider notification: %v", err)
	}
	p.write(t, frame)
}

func (p *rawProviderPeer) write(t *testing.T, frame []byte) {
	t.Helper()
	if err := p.connection.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.connection.SetWriteDeadline(time.Time{}) }()
	if err := writeFrame(p.connection, frame, p.maximum); err != nil {
		t.Fatalf("write raw provider frame: %v", err)
	}
}

func rawTestCommand(t *testing.T, capability protocol.CapabilityName, delivery protocol.DeliveryClass, sessionID string, payload any) protocol.Command {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Command{
		ProtocolVersion:   protocol.Version,
		CommandID:         "client-command-1",
		SessionID:         sessionID,
		Capability:        capability,
		IdempotencyKey:    "client-idempotency-1",
		CancellationToken: "client-cancellation-1",
		Deadline:          time.Now().Add(time.Minute).UTC(),
		DeliveryClass:     delivery,
		Payload:           raw,
	}
}

func subscribeRawTerminal(t *testing.T, client *Client, peer *rawProviderPeer, request protocol.TerminalSubscribeRequest) protocol.EventsSubscribeResult {
	t.Helper()
	result := make(chan protocol.EventsSubscribeResult, 1)
	errors := make(chan error, 1)
	go func() {
		value, err := client.SubscribeTerminal(context.Background(), request)
		result <- value
		errors <- err
	}()
	rpcRequest := peer.readRequest(t)
	if rpcRequest.Method != "terminal.subscribe" {
		t.Fatalf("subscription method = %q, want terminal.subscribe", rpcRequest.Method)
	}
	peer.respond(t, rpcRequest, protocol.EventsSubscribeResult{SubscriptionID: "raw-terminal-subscription", Cursors: []protocol.EventSubscriptionCursor{}})
	if err := <-errors; err != nil {
		t.Fatalf("SubscribeTerminal: %v", err)
	}
	return <-result
}

func rawTerminalChunk(sequence, offset uint64, data string, remaining uint64, replayed bool) protocol.TerminalChunk {
	return protocol.TerminalChunk{
		NativeSessionID: "native-session-1",
		StreamID:        "stdout",
		Encoding:        protocol.TerminalEncodingUTF8,
		Sequence:        sequence,
		Offset:          offset,
		ObservedAt:      time.Now().UTC(),
		Data:            data,
		Replayed:        replayed,
		Redactions:      []protocol.TerminalRedaction{},
		CreditRemaining: remaining,
	}
}

func unsafeRawRuntimeResult() protocol.RuntimeSessionResult {
	now := time.Now().UTC()
	state := func(axis protocol.StateAxis, value protocol.State) protocol.StateReport {
		return protocol.StateReport{
			Axis: axis, State: value, Source: "raw-provider", ObservedAt: now,
			Sequence: 1, Confidence: 1, Authority: protocol.AuthorityAuthoritative,
		}
	}
	return protocol.RuntimeSessionResult{Session: protocol.RuntimeSession{
		ProviderID:      "raw-provider",
		NativeSessionID: "native-session-1",
		Lifecycle:       state(protocol.AxisLifecycle, protocol.LifecycleRunning),
		Health:          state(protocol.AxisHealth, protocol.HealthHealthy),
		Extensions:      map[string]json.RawMessage{"dev.example/runtime": json.RawMessage(`{"nested":{"tenant_id":"forged"}}`)},
	}}
}

func chunkPointer(chunk protocol.TerminalChunk) *protocol.TerminalChunk { return &chunk }

func waitRawNotification(t *testing.T, client *Client, method string) Notification {
	t.Helper()
	select {
	case notification, ok := <-client.Notifications():
		if !ok {
			client.mu.Lock()
			err := client.readErr
			client.mu.Unlock()
			t.Fatalf("client notification stream closed: %v", err)
		}
		if notification.Method != method {
			t.Fatalf("notification method = %q, want %q", notification.Method, method)
		}
		return notification
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", method)
		return Notification{}
	}
}

func waitClientFailure(t *testing.T, client *Client, code protocol.ErrorCode) {
	t.Helper()
	select {
	case <-client.done:
		client.mu.Lock()
		err := client.readErr
		client.mu.Unlock()
		if !protocol.IsCode(err, code) {
			t.Fatalf("client failure = %v, want %s", err, code)
		}
	case <-time.After(time.Second):
		t.Fatalf("client did not fail with %s", code)
	}
}

func closeRawProviderClient(t *testing.T, client *Client, peer *rawProviderPeer) {
	t.Helper()
	if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("Client.Close: %v", err)
	}
	if err := peer.connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("raw provider close: %v", err)
	}
}
