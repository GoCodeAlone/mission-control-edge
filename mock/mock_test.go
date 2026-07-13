package mock_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/mock"
	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

func TestFaultsAreDeterministicAndComposable(t *testing.T) {
	t.Parallel()

	faults, err := mock.NewFaults(
		mock.Fault{Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 2},
		mock.Fault{Point: mock.PointControlPlaneIngest, Occurrence: 2, Action: mock.ActionOutOfOrder},
		mock.Fault{Point: mock.PointControlPlaneReplay, Occurrence: 1, Action: mock.ActionRedact, Match: []byte("secret"), Replacement: []byte("[redacted]")},
		mock.Fault{Point: mock.PointControlPlaneReplay, Occurrence: 1, Action: mock.ActionOversize, Size: 32},
	)
	if err != nil {
		t.Fatalf("NewFaults: %v", err)
	}

	frames, err := faults.Apply(context.Background(), mock.PointControlPlaneIngest, []byte("one"))
	if err != nil {
		t.Fatalf("duplicate: %v", err)
	}
	if len(frames) != 2 || string(frames[0]) != "one" || string(frames[1]) != "one" {
		t.Fatalf("duplicate frames = %q", frames)
	}
	frames, err = faults.Apply(context.Background(), mock.PointControlPlaneIngest, []byte("two"))
	if err != nil || len(frames) != 0 {
		t.Fatalf("held frames = %q, %v", frames, err)
	}
	frames, err = faults.Apply(context.Background(), mock.PointControlPlaneIngest, []byte("three"))
	if err != nil {
		t.Fatalf("release reorder: %v", err)
	}
	if len(frames) != 2 || string(frames[0]) != "three" || string(frames[1]) != "two" {
		t.Fatalf("reordered frames = %q", frames)
	}

	frames, err = faults.Apply(context.Background(), mock.PointControlPlaneReplay, []byte("secret"))
	if err != nil {
		t.Fatalf("redact/oversize: %v", err)
	}
	if len(frames) != 1 || len(frames[0]) != 32 || bytes.Contains(frames[0], []byte("secret")) || !bytes.Contains(frames[0], []byte("[redacted]")) {
		t.Fatalf("redacted oversized frame = %q", frames)
	}
	if got := faults.Remaining(); got != 0 {
		t.Fatalf("remaining faults = %d", got)
	}
}

func TestFaultDuplicateOutputIsBounded(t *testing.T) {
	t.Parallel()

	faults, err := mock.NewFaults(
		mock.Fault{Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 16},
		mock.Fault{Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 16},
		mock.Fault{Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 16},
	)
	if err != nil {
		t.Fatalf("NewFaults: %v", err)
	}

	if _, err := faults.Apply(context.Background(), mock.PointControlPlaneIngest, []byte("frame")); err == nil {
		t.Fatal("duplicate fault expansion succeeded beyond the output limit")
	}
}

func TestFaultWaitsHonorCancellation(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	faults, err := mock.NewFaults(
		mock.Fault{Point: mock.PointGatewayToProvider, Occurrence: 1, Action: mock.ActionBackpressure, Gate: gate},
		mock.Fault{Point: mock.PointGatewayToProvider, Occurrence: 2, Action: mock.ActionDelay, Delay: time.Hour},
	)
	if err != nil {
		t.Fatalf("NewFaults: %v", err)
	}
	for occurrence := 1; occurrence <= 2; occurrence++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, applyErr := faults.Apply(ctx, mock.PointGatewayToProvider, []byte("frame"))
		cancel()
		if !errors.Is(applyErr, context.DeadlineExceeded) {
			t.Fatalf("occurrence %d error = %v", occurrence, applyErr)
		}
	}
}

func TestFaultCanTargetOneNotificationFrame(t *testing.T) {
	t.Parallel()

	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointProviderToGateway, Occurrence: 1, Action: mock.ActionReplayGap,
		Contains: []byte(`"method":"$mc/event"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	frames, err := faults.Apply(context.Background(), mock.PointProviderToGateway, []byte(`{"id":"response"}`))
	if err != nil || len(frames) != 1 {
		t.Fatalf("unmatched frame = %q, %v", frames, err)
	}
	if got := faults.Remaining(); got != 1 {
		t.Fatalf("remaining after unmatched frame = %d", got)
	}
	frames, err = faults.Apply(context.Background(), mock.PointProviderToGateway, []byte(`{"method":"$mc/event"}`))
	if err != nil || len(frames) != 0 {
		t.Fatalf("matched frame = %q, %v", frames, err)
	}
}

func TestGatewayInjectsFaultsAtWholeFrameBoundaries(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	t.Cleanup(func() { _ = providerSide.Close() })
	faults, err := mock.NewFaults(
		mock.Fault{Point: mock.PointGatewayToProvider, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 2},
		mock.Fault{Point: mock.PointProviderToGateway, Occurrence: 1, Action: mock.ActionOutOfOrder},
	)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(gatewaySide, faults)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	requestDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(providerSide)
		for range 2 {
			frame, readErr := reader.ReadString('\n')
			if readErr != nil {
				requestDone <- readErr
				return
			}
			if frame != "request\n" {
				requestDone <- errors.New("unexpected request frame")
				return
			}
		}
		requestDone <- nil
	}()
	if _, err := gateway.Write([]byte("request\n")); err != nil {
		t.Fatalf("gateway write: %v", err)
	}
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}

	responseDone := make(chan error, 1)
	go func() {
		if _, writeErr := io.WriteString(providerSide, "first\nsecond\n"); writeErr != nil {
			responseDone <- writeErr
			return
		}
		responseDone <- nil
	}()
	reader := bufio.NewReader(gateway)
	first, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("first response: %v", err)
	}
	second, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("second response: %v", err)
	}
	if first != "second\n" || second != "first\n" {
		t.Fatalf("responses = %q, %q", first, second)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
}

func TestGatewayBackpressureBlocksTheOriginatingWrite(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	t.Cleanup(func() { _ = providerSide.Close() })
	gate := make(chan struct{})
	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointGatewayToProvider, Occurrence: 1, Action: mock.ActionBackpressure, Gate: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(gatewaySide, faults)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	readDone := make(chan error, 1)
	go func() {
		_, readErr := bufio.NewReader(providerSide).ReadString('\n')
		readDone <- readErr
	}()
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := gateway.Write([]byte("request\n"))
		writeDone <- writeErr
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("write bypassed backpressure: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(gate)
	if err := <-writeDone; err != nil {
		t.Fatalf("released write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("provider read: %v", err)
	}
}

func TestGatewayBoundsUnterminatedProviderOutput(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	gateway, err := mock.NewGateway(gatewaySide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	go func() {
		_, _ = providerSide.Write(bytes.Repeat([]byte{'x'}, protocol.MaxMessageBytes+2))
		_ = providerSide.Close()
	}()
	output, err := io.ReadAll(gateway)
	if !errors.Is(err, mock.ErrFrameTooLarge) {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(output) != protocol.MaxMessageBytes+2 || output[len(output)-1] != '\n' {
		t.Fatalf("bounded output length/terminator = %d/%q", len(output), output[len(output)-1:])
	}
}

func TestGatewayBoundsUnterminatedClientOutput(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	t.Cleanup(func() { _ = providerSide.Close() })
	gateway, err := mock.NewGateway(gatewaySide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	if written, err := gateway.Write(bytes.Repeat([]byte{'x'}, protocol.MaxMessageBytes+1)); !errors.Is(err, mock.ErrFrameTooLarge) || written != 0 {
		t.Fatalf("oversized client write = %d, %v", written, err)
	}
}

func TestGatewayFlushesHeldCompleteFrameBeforeTrailingFragment(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointProviderToGateway, Occurrence: 1, Action: mock.ActionOutOfOrder,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(gatewaySide, faults)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	go func() {
		_, _ = io.WriteString(providerSide, "complete\npartial")
		_ = providerSide.Close()
	}()
	output, err := io.ReadAll(gateway)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(output) != "complete\npartial" {
		t.Fatalf("output = %q", output)
	}
}

func TestGatewayDoesNotHideAnInvalidEmptyFrame(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	gateway, err := mock.NewGateway(gatewaySide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	go func() {
		_, _ = io.WriteString(providerSide, "\n")
		_ = providerSide.Close()
	}()
	output, err := io.ReadAll(gateway)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(output) != "\n" {
		t.Fatalf("output = %q", output)
	}
}

func TestGatewayDisconnectFaultPropagatesToTheOriginatingWrite(t *testing.T) {
	t.Parallel()

	providerSide, gatewaySide := net.Pipe()
	t.Cleanup(func() { _ = providerSide.Close() })
	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointGatewayToProvider, Occurrence: 1, Action: mock.ActionDisconnect,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(gatewaySide, faults)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Write([]byte("request\n")); !errors.Is(err, mock.ErrDisconnected) {
		t.Fatalf("write error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := gateway.Wait(ctx); !errors.Is(err, mock.ErrDisconnected) {
		t.Fatalf("gateway error = %v", err)
	}
}

func TestGatewayDelayExercisesRealProviderClientDeadline(t *testing.T) {
	t.Parallel()

	manifest := runtimeManifest(t)
	now := time.Now().UTC()
	server, err := provider.NewServer(provider.ServerConfig{
		Manifest:            manifest,
		AuthenticationModes: []string{"none"},
	}, provider.HandlerSet{Provider: provider.ProviderHandlers{
		Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
			return protocol.ProviderHealthResult{
				ProviderID: manifest.ID,
				Health: protocol.StateReport{
					Axis: protocol.AxisHealth, State: protocol.HealthHealthy, Source: "fixture",
					ObservedAt: now, Sequence: 1, Confidence: 1, Authority: protocol.AuthorityAuthoritative,
				},
			}, nil
		},
	}}, provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	serverSide, gatewaySide := net.Pipe()
	serveCtx, cancelServe := context.WithCancel(context.Background())
	t.Cleanup(cancelServe)
	go func() { _ = server.ServeConn(serveCtx, serverSide) }()

	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointProviderToGateway, Occurrence: 2, Action: mock.ActionDelay, Delay: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(gatewaySide, faults)
	if err != nil {
		t.Fatal(err)
	}
	client, err := gateway.Client(provider.WithLimits(provider.TestLimits()))
	if err != nil {
		t.Fatalf("Client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.Initialize(context.Background(), initializeRequest(manifest)); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Health(ctx); !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
		t.Fatalf("Health error = %v", err)
	}
}

func TestExternalProviderCanBeCrashedDeterministically(t *testing.T) {
	if os.Getenv("MC_MOCK_HELPER_PROCESS") == "1" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}

	process, err := mock.StartProvider(context.Background(), mock.ProviderConfig{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExternalProviderCanBeCrashedDeterministically"},
		Env:  []string{"MC_MOCK_HELPER_PROCESS=1"},
	})
	if err != nil {
		t.Fatalf("StartProvider: %v", err)
	}
	t.Cleanup(func() { _ = process.Close() })
	if process.PID() <= 0 {
		t.Fatalf("PID = %d", process.PID())
	}
	if err := process.Crash(); err != nil {
		t.Fatalf("Crash: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := process.Wait(ctx); err == nil {
		t.Fatal("crashed process exited successfully")
	}

	faultedProcess, err := mock.StartProvider(context.Background(), mock.ProviderConfig{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExternalProviderCanBeCrashedDeterministically"},
		Env:  []string{"MC_MOCK_HELPER_PROCESS=1"},
	})
	if err != nil {
		t.Fatalf("start faulted provider: %v", err)
	}
	t.Cleanup(func() { _ = faultedProcess.Close() })
	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointGatewayToProvider, Occurrence: 1, Action: mock.ActionCrash,
	})
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := mock.NewGateway(faultedProcess, faults)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gateway.Write([]byte("request\n")); !errors.Is(err, mock.ErrCrash) {
		t.Fatalf("faulted write error = %v", err)
	}
	if err := faultedProcess.Wait(ctx); err == nil {
		t.Fatal("fault-crashed process exited successfully")
	}
}

func TestExternalProviderOutputSurvivesImmediateProcessExit(t *testing.T) {
	if os.Getenv("MC_MOCK_OUTPUT_HELPER") == "1" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'x'}, 1024))
		os.Exit(0)
	}

	process, err := mock.StartProvider(context.Background(), mock.ProviderConfig{
		Path: os.Args[0],
		Args: []string{"-test.run=TestExternalProviderOutputSurvivesImmediateProcessExit"},
		Env:  []string{"MC_MOCK_OUTPUT_HELPER=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Close() })
	<-process.Exited()
	output, err := io.ReadAll(process)
	if err != nil {
		t.Fatalf("read provider output: %v", err)
	}
	if len(output) != 1024 {
		t.Fatalf("provider output bytes = %d", len(output))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := process.Wait(ctx); err != nil {
		t.Fatalf("provider exit: %v", err)
	}
}

func TestControlPlaneSurfacesDuplicateOutOfOrderAndReplayGap(t *testing.T) {
	t.Parallel()

	duplicateFaults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionDuplicate, Copies: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	control := mock.NewControlPlane(duplicateFaults)
	results, err := control.Ingest(context.Background(), canonicalEvent(t))
	if err != nil {
		t.Fatalf("duplicate ingest: %v", err)
	}
	if len(results) != 2 || results[0].Outcome != protocol.SequenceAccepted || results[1].Outcome != protocol.SequenceDuplicate {
		t.Fatalf("duplicate outcomes = %#v", results)
	}
	if got := len(control.Records()); got != 1 {
		t.Fatalf("duplicate record count = %d", got)
	}

	reorderFaults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointControlPlaneIngest, Occurrence: 2, Action: mock.ActionOutOfOrder,
	})
	if err != nil {
		t.Fatal(err)
	}
	reordered := mock.NewControlPlane(reorderFaults)
	first := canonicalEvent(t)
	first.ProviderEvent.Sequence = 1
	first.ProviderEvent.EventID = "event-1"
	second := first
	second.ProviderEvent.Sequence = 2
	second.ProviderEvent.EventID = "event-2"
	third := first
	third.ProviderEvent.Sequence = 3
	third.ProviderEvent.EventID = "event-3"
	if results, err := reordered.Ingest(context.Background(), first); err != nil || len(results) != 1 || results[0].Outcome != protocol.SequenceAccepted {
		t.Fatalf("baseline first event = %#v, %v", results, err)
	}
	if results, err := reordered.Ingest(context.Background(), second); err != nil || len(results) != 0 {
		t.Fatalf("held second event = %#v, %v", results, err)
	}
	results, err = reordered.Ingest(context.Background(), third)
	if err != nil {
		t.Fatalf("reordered third event: %v", err)
	}
	if len(results) != 2 || results[0].Event.ProviderEvent.EventID != "event-3" || results[0].Outcome != protocol.SequenceGap || results[1].Event.ProviderEvent.EventID != "event-2" {
		t.Fatalf("reordered outcomes = %#v", results)
	}

	replayFaults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointControlPlaneReplay, Occurrence: 2, Action: mock.ActionReplayGap,
	})
	if err != nil {
		t.Fatal(err)
	}
	replay := mock.NewControlPlane(replayFaults)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		event := canonicalEvent(t)
		event.ProviderEvent.Sequence = sequence
		event.ProviderEvent.EventID = "replay-event-" + string(rune('0'+sequence))
		if _, err := replay.Ingest(context.Background(), event); err != nil {
			t.Fatalf("ingest replay event %d: %v", sequence, err)
		}
	}
	records, err := replay.Replay(context.Background(), 0)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(records) != 2 || records[0].JournalSequence != 1 || records[1].JournalSequence != 3 {
		t.Fatalf("replay records = %#v", records)
	}
}

func TestControlPlaneDeduplicatesProviderEventAcrossGatewayEnvelopeChanges(t *testing.T) {
	t.Parallel()

	control := mock.NewControlPlane(nil)
	first := canonicalEvent(t)
	results, err := control.Ingest(context.Background(), first)
	if err != nil || len(results) != 1 || results[0].Outcome != protocol.SequenceAccepted {
		t.Fatalf("first ingest = %#v, %v", results, err)
	}
	duplicate := first
	duplicate.GatewayID = "gateway-retry"
	duplicate.CorrelationID = "correlation-retry"
	results, err = control.Ingest(context.Background(), duplicate)
	if err != nil {
		t.Fatalf("duplicate ingest: %v", err)
	}
	if len(results) != 1 || results[0].Outcome != protocol.SequenceDuplicate || results[0].JournalSequence != 0 {
		t.Fatalf("duplicate outcome = %#v", results)
	}
	if got := len(control.Records()); got != 1 {
		t.Fatalf("duplicate record count = %d", got)
	}
}

func TestControlPlaneAppliesRedactionAndRejectsOversize(t *testing.T) {
	t.Parallel()

	faults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionRedact,
		Match: []byte("approval pending"), Replacement: []byte("[redacted]"),
	})
	if err != nil {
		t.Fatal(err)
	}
	control := mock.NewControlPlane(faults)
	if _, err := control.Ingest(context.Background(), canonicalEvent(t)); err != nil {
		t.Fatalf("redacted ingest: %v", err)
	}
	encoded, err := json.Marshal(control.Records())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("approval pending")) || !bytes.Contains(encoded, []byte("[redacted]")) {
		t.Fatalf("stored records were not redacted: %s", encoded)
	}

	oversizeFaults, err := mock.NewFaults(mock.Fault{
		Point: mock.PointControlPlaneIngest, Occurrence: 1, Action: mock.ActionOversize,
		Size: protocol.MaxMessageBytes + 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	oversize := mock.NewControlPlane(oversizeFaults)
	if _, err := oversize.Ingest(context.Background(), canonicalEvent(t)); !protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		t.Fatalf("oversize error = %v", err)
	}
}

func canonicalEvent(t *testing.T) protocol.CanonicalEvent {
	t.Helper()
	data, err := os.ReadFile("../protocol/testdata/valid/canonical-event.json")
	if err != nil {
		t.Fatal(err)
	}
	var event protocol.CanonicalEvent
	if err := protocol.Decode(data, &event); err != nil {
		t.Fatal(err)
	}
	return event
}

func runtimeManifest(t *testing.T) protocol.ProviderManifest {
	t.Helper()
	data, err := os.ReadFile("../protocol/testdata/valid/provider-manifest-runtime.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest protocol.ProviderManifest
	if err := protocol.Decode(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Capabilities = []protocol.CapabilityDescriptor{
		mustCapability(t, "provider.initialize"),
		mustCapability(t, "provider.capabilities"),
		mustCapability(t, "provider.health"),
	}
	return manifest
}

func mustCapability(t *testing.T, name protocol.CapabilityName) protocol.CapabilityDescriptor {
	t.Helper()
	capability, ok := protocol.Capability(name)
	if !ok {
		t.Fatalf("missing capability %q", name)
	}
	return capability
}

func initializeRequest(manifest protocol.ProviderManifest) protocol.ProviderInitializeRequest {
	return protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.Version}, GatewayVersion: "1.0.0",
		Platform: manifest.Platforms[0], RequiredCapabilities: []protocol.CapabilityName{"provider.initialize"},
		MaximumMessageBytes: protocol.MaxMessageBytes, MaximumChunkBytes: protocol.MaxTerminalChunkBytes,
		AuthenticationModes: []string{"none"}, ExperimentalFeatures: []string{},
	}
}
