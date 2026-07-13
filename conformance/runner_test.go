package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/mock"
	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

const helperEnvironment = "MC_CONFORMANCE_EXTERNAL_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnvironment) == "1" {
		os.Exit(runExternalProviderFixture())
	}
	os.Exit(m.Run())
}

func TestDefaultMatrixCoversRequiredFailureClasses(t *testing.T) {
	t.Parallel()

	matrix, err := DefaultMatrix()
	if err != nil {
		t.Fatalf("DefaultMatrix: %v", err)
	}
	if err := matrix.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	wantKinds := []CaseKind{
		CaseInitializeRequired,
		CaseOptionalCapabilities,
		CaseCapabilityMapping,
		CaseNotSupported,
		CaseEventDuplicate,
		CaseEventOutOfOrder,
		CaseReplayGap,
		CaseReconnect,
		CaseCancellation,
		CaseDeadline,
		CaseBackpressure,
		CaseOversizedFrame,
		CaseCrashRecovery,
		CaseRedaction,
		CaseDeliveryClass,
	}
	for _, kind := range wantKinds {
		if !matrix.HasKind(kind) {
			t.Errorf("default matrix does not contain %q", kind)
		}
	}
	for _, class := range []protocol.DeliveryClass{
		protocol.DeliveryProviderIdempotent,
		protocol.DeliveryStateReconciled,
		protocol.DeliveryAtMostOnce,
	} {
		if !matrix.HasDeliveryClass(class) {
			t.Errorf("default matrix does not contain delivery class %q", class)
		}
	}
}

func TestMatrixRejectsUnknownAndDuplicateCases(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"unknown field":  `{"schema_version":"mission-control.conformance.cases.v1alpha1","suite_version":"0.1.0","cases":[],"extra":true}`,
		"duplicate case": `{"schema_version":"mission-control.conformance.cases.v1alpha1","suite_version":"0.1.0","cases":[{"id":"duplicate.case","description":"one","kind":"reconnect","required":true},{"id":"duplicate.case","description":"two","kind":"reconnect","required":true}]}`,
		"unknown kind":   `{"schema_version":"mission-control.conformance.cases.v1alpha1","suite_version":"0.1.0","cases":[{"id":"unknown.kind","description":"unknown","kind":"invented","required":true}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadMatrix(strings.NewReader(input)); err == nil {
				t.Fatal("LoadMatrix accepted an invalid matrix")
			}
		})
	}
}

func TestInitializeRequestUsesPortableWireArrays(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(initializeRequest(negotiatedMaximum, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"experimental_features":null`)) {
		t.Fatalf("initialization request used a Go-only null slice: %s", encoded)
	}
	if !bytes.Contains(encoded, []byte(`"experimental_features":[]`)) {
		t.Fatalf("initialization request lacks a portable empty feature array: %s", encoded)
	}
}

func TestCapabilityCaseMapCoversEveryAdvertisedCapability(t *testing.T) {
	t.Parallel()

	matrix, err := DefaultMatrix()
	if err != nil {
		t.Fatalf("DefaultMatrix: %v", err)
	}
	manifest := fixtureManifest()
	mapping := matrix.CapabilityCaseMap(manifest)
	for _, descriptor := range manifest.Capabilities {
		ids := mapping[descriptor.Name]
		if !slices.Contains(ids, "capability.mapping") {
			t.Errorf("%q mapping = %v, missing capability.mapping", descriptor.Name, ids)
		}
		if descriptor.Mutating && !slices.Contains(ids, "delivery."+string(descriptor.DeliveryClass)) {
			t.Errorf("%q mapping = %v, missing delivery class case", descriptor.Name, ids)
		}
	}
	if got := mapping["events.subscribe"]; !slices.Contains(got, "events.duplicate") || !slices.Contains(got, "events.out_of_order") || !slices.Contains(got, "events.replay_gap") {
		t.Fatalf("events.subscribe mapping = %v", got)
	}
}

func TestCapabilityCaseMapDoesNotClaimAnUntestedDeliveryCapability(t *testing.T) {
	t.Parallel()

	matrix, err := DefaultMatrix()
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixtureManifest()
	shutdown, ok := protocol.Capability("provider.shutdown")
	if !ok {
		t.Fatal("provider.shutdown descriptor is missing")
	}
	manifest.Capabilities = append(manifest.Capabilities, shutdown)
	mapping := matrix.CapabilityCaseMap(manifest)
	if slices.Contains(mapping["provider.shutdown"], "delivery.provider_idempotent") {
		t.Fatalf("provider.shutdown mapping overclaimed executable delivery evidence: %v", mapping["provider.shutdown"])
	}
}

func TestUnsupportedCapabilityProbeCannotCollideWithManifest(t *testing.T) {
	t.Parallel()

	manifest := fixtureManifest()
	manifest.Capabilities = append(manifest.Capabilities, protocol.CapabilityDescriptor{
		Name: "example.conformance/unsupported", Role: protocol.RoleProvider,
	})
	probe := unsupportedCapability(manifest)
	if probe == "" || manifest.Supports(probe) {
		t.Fatalf("unsupported capability probe = %q", probe)
	}
}

func TestRunnerExercisesOnlyExternalProviderProcesses(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "provider-pids")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	report, err := Run(ctx, RunnerConfig{
		ProviderCommand: []string{os.Args[0]},
		Environment:     []string{helperEnvironment + "=1", "MC_CONFORMANCE_PID_FILE=" + pidFile},
		CaseTimeout:     750 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.HasRequiredFailures() {
		var diagnostic bytes.Buffer
		_ = WriteJSON(&diagnostic, report)
		t.Fatalf("required conformance failure:\n%s", diagnostic.String())
	}
	if report.ProviderID != "conformance-external-provider" || report.ProtocolVersion != protocol.Version {
		t.Fatalf("provider identity = %q protocol=%q", report.ProviderID, report.ProtocolVersion)
	}
	data, err := os.ReadFile(pidFile) // #nosec G304 -- pidFile is inside this test's t.TempDir.
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Fields(string(data))
	if len(lines) < 8 {
		t.Fatalf("external provider launches = %d, want at least 8", len(lines))
	}
	for _, line := range lines {
		if line == fmt.Sprint(os.Getpid()) {
			t.Fatalf("runner used the test process as an in-process provider: %s", line)
		}
	}
}

func TestRunnerRequiredFailureControlsOutcome(t *testing.T) {
	t.Parallel()

	matrix := Matrix{
		SchemaVersion: CaseSchemaVersion,
		SuiteVersion:  "0.1.0",
		Cases: []Case{
			{ID: "required.case", Description: "required", Kind: CaseInitializeRequired, Required: true},
			{ID: "optional.case", Description: "optional", Kind: CaseInitializeRequired, Required: false},
		},
	}
	report, err := Run(context.Background(), RunnerConfig{
		ProviderCommand: []string{filepath.Join(t.TempDir(), "missing-provider")},
		Matrix:          matrix,
		CaseTimeout:     250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !report.HasRequiredFailures() {
		t.Fatal("required provider launch failure did not fail the report")
	}
	if got := report.Result("required.case"); got.Status != StatusFailed || !got.Required {
		t.Fatalf("required result = %#v", got)
	}
	if got := report.Result("optional.case"); got.Status != StatusFailed || got.Required {
		t.Fatalf("optional result = %#v", got)
	}
}

func TestRunnerRejectsProviderManifestDriftAcrossCases(t *testing.T) {
	t.Parallel()

	matrix := Matrix{
		SchemaVersion: CaseSchemaVersion,
		SuiteVersion:  "0.1.0",
		Cases: []Case{
			{ID: "contract.first", Description: "first contract", Kind: CaseInitializeRequired, Required: true},
			{ID: "contract.second", Description: "second contract", Kind: CaseInitializeRequired, Required: true},
		},
	}
	launches := filepath.Join(t.TempDir(), "provider-launches")
	report, err := Run(context.Background(), RunnerConfig{
		ProviderCommand: []string{os.Args[0]},
		Environment: []string{
			helperEnvironment + "=1",
			"MC_CONFORMANCE_PID_FILE=" + launches,
			"MC_CONFORMANCE_DRIFT=1",
		},
		Matrix:      matrix,
		CaseTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result := report.Result("contract.second")
	if result.Status != StatusFailed || result.ErrorCode != protocol.CodeInvalidArgument || result.Summary != "invalid_protocol_result" {
		t.Fatalf("drift result = %#v", result)
	}
}

func TestRecoveryCasesRejectProviderContractDrift(t *testing.T) {
	t.Parallel()

	for _, kind := range []CaseKind{CaseReconnect, CaseCrashRecovery} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			launches := filepath.Join(t.TempDir(), "provider-launches")
			matrix := Matrix{
				SchemaVersion: CaseSchemaVersion,
				SuiteVersion:  "0.1.0",
				Cases: []Case{{
					ID: "contract." + string(kind), Description: "stable recovery contract", Kind: kind, Required: true,
				}},
			}
			report, err := Run(context.Background(), RunnerConfig{
				ProviderCommand: []string{os.Args[0]},
				Environment: []string{
					helperEnvironment + "=1",
					"MC_CONFORMANCE_PID_FILE=" + launches,
					"MC_CONFORMANCE_DRIFT=1",
				},
				Matrix:      matrix,
				CaseTimeout: time.Second,
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			result := report.Result("contract." + string(kind))
			if result.Status != StatusFailed || result.ErrorCode != protocol.CodeInvalidArgument || result.Summary != "invalid_protocol_result" {
				t.Fatalf("recovery drift result = %#v", result)
			}
		})
	}
}

func TestRedactionCaseFailsClosedWhenDiagnosticsExceedBound(t *testing.T) {
	t.Parallel()

	matrix := Matrix{
		SchemaVersion: CaseSchemaVersion,
		SuiteVersion:  "0.1.0",
		Cases: []Case{{
			ID:          "security.redaction.bound",
			Description: "redaction bound",
			Kind:        CaseRedaction,
			Required:    true,
		}},
	}
	report, err := Run(context.Background(), RunnerConfig{
		ProviderCommand: []string{os.Args[0]},
		Environment:     []string{helperEnvironment + "=1", "MC_CONFORMANCE_NOISY_SECRET=1"},
		Matrix:          matrix,
		CaseTimeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	result := report.Result("security.redaction.bound")
	if result.Status != StatusFailed || result.Summary != "diagnostics_limit_exceeded" {
		t.Fatalf("redaction overflow result = %#v", result)
	}
}

func TestOversizedFrameCaseRejectsAProviderThatBreaksTheNegotiatedConnection(t *testing.T) {
	t.Parallel()

	matrix := Matrix{
		SchemaVersion: CaseSchemaVersion,
		SuiteVersion:  "0.1.0",
		Cases: []Case{{
			ID: "transport.oversized.injected", Description: "injected oversized response", Kind: CaseOversizedFrame, Required: true,
		}},
	}
	report, err := Run(context.Background(), RunnerConfig{
		ProviderCommand: []string{os.Args[0]},
		Environment:     []string{helperEnvironment + "=1"},
		Matrix:          matrix,
		CaseTimeout:     time.Second,
		FaultPlan: func(Case) (*mock.Faults, error) {
			return mock.NewFaults(mock.Fault{
				Point: mock.PointProviderToGateway, Occurrence: 2,
				Action: mock.ActionOversize, Size: 513,
			})
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result := report.Result("transport.oversized.injected"); result.Status != StatusFailed {
		t.Fatalf("oversized response result = %#v", result)
	}
}

func TestReportsAreDeterministicAndContentSafe(t *testing.T) {
	t.Parallel()

	report := Report{
		SchemaVersion:   ReportSchemaVersion,
		SuiteVersion:    "0.1.0",
		ProviderID:      "provider-report",
		ProviderVersion: "1.2.3",
		ProtocolVersion: protocol.Version,
		StartedAt:       time.Date(2026, 7, 11, 20, 0, 0, 0, time.UTC),
		FinishedAt:      time.Date(2026, 7, 11, 20, 0, 1, 0, time.UTC),
		Results: []CaseResult{
			{ID: "required.pass", Description: "pass", Required: true, Status: StatusPassed, DurationMillis: 1000},
			{ID: "optional.skip", Description: "skip", Required: false, Status: StatusSkipped, Summary: "capability_not_advertised"},
			{ID: "required.fail", Description: "fail <safe>", Required: true, Status: StatusFailed, ErrorCode: protocol.CodeUnavailable, Summary: "provider_unavailable"},
		},
		CapabilityCases: map[protocol.CapabilityName][]string{"provider.initialize": {"required.pass"}},
	}
	var jsonReport bytes.Buffer
	if err := WriteJSON(&jsonReport, report); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(jsonReport.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON report: %v", err)
	}
	if !decoded.HasRequiredFailures() {
		t.Fatal("JSON report lost required failure")
	}
	var junit bytes.Buffer
	if err := WriteJUnit(&junit, report); err != nil {
		t.Fatalf("WriteJUnit: %v", err)
	}
	text := junit.String()
	for _, expected := range []string{`tests="3"`, `failures="1"`, `skipped="1"`, `fail &lt;safe&gt;`, `<failure`, `<skipped`} {
		if !strings.Contains(text, expected) {
			t.Errorf("JUnit report missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(jsonReport.String()+text, "MC_CONFORMANCE_SECRET") {
		t.Fatal("report exposed secret content")
	}
}

func TestCLIExitsNonzeroAndWritesReportsOnRequiredFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the conformance command")
	}
	t.Parallel()

	temporary := t.TempDir()
	binary := filepath.Join(temporary, "mc-conformance")
	build := exec.Command("go", "build", "-o", binary, "./cmd/mc-conformance") // #nosec G204 -- the test builds a fixed repository package into t.TempDir.
	build.Dir = moduleRoot(t)
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build mc-conformance: %v: %s", err, output)
	}
	jsonPath := filepath.Join(temporary, "report.json")
	junitPath := filepath.Join(temporary, "report.xml")
	command := exec.Command(binary, // #nosec G204 -- binary is the fixed conformance command just built into t.TempDir.
		"--provider", filepath.Join(temporary, "missing-provider"),
		"--json", jsonPath,
		"--junit", junitPath,
		"--timeout", "100ms",
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 1 {
		t.Fatalf("mc-conformance error = %v, output=%q, want exit 1", err, output)
	}
	data, err := os.ReadFile(jsonPath) // #nosec G304 -- jsonPath is inside this test's t.TempDir.
	if err != nil {
		t.Fatalf("read JSON report: %v", err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}
	if !report.HasRequiredFailures() {
		t.Fatal("CLI report did not retain required failure")
	}
	if data, err := os.ReadFile(junitPath); err != nil || !bytes.Contains(data, []byte(`<failure`)) { // #nosec G304 -- junitPath is inside this test's t.TempDir.
		t.Fatalf("JUnit report = %q, err=%v", data, err)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("module root: %v", err)
	}
	return root
}

func runExternalProviderFixture() int {
	if path := os.Getenv("MC_CONFORMANCE_PID_FILE"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 G703 -- the parent test supplies its t.TempDir fixture path.
		if err != nil {
			return 2
		}
		_, _ = fmt.Fprintln(file, os.Getpid())
		_ = file.Close()
	}
	if os.Getenv("MC_CONFORMANCE_NOISY_SECRET") == "1" {
		_, _ = fmt.Fprint(os.Stderr, strings.Repeat("x", stderrLimit+1), os.Getenv("MC_CONFORMANCE_SECRET_MARKER"))
	}
	manifest := fixtureManifest()
	if os.Getenv("MC_CONFORMANCE_DRIFT") == "1" {
		data, err := os.ReadFile(os.Getenv("MC_CONFORMANCE_PID_FILE")) // #nosec G304 G703 -- the parent test supplies its t.TempDir fixture path.
		if err != nil {
			return 2
		}
		if len(strings.Fields(string(data))) > 1 {
			manifest.Version = "1.0.1"
		}
	}
	var calls atomic.Uint64
	handlers := provider.HandlerSet{
		Provider: provider.ProviderHandlers{
			Health: func(context.Context, protocol.ProviderHealthRequest) (protocol.ProviderHealthResult, error) {
				return protocol.ProviderHealthResult{ProviderID: manifest.ID, Health: fixtureState(protocol.AxisHealth, protocol.HealthHealthy, 1)}, nil
			},
			Events: provider.EventHandlers{
				Subscribe: func(context.Context, protocol.EventsSubscribeRequest) (provider.EventSubscription, error) {
					events := fixtureEvents(manifest.ID)
					return provider.EventSubscription{
						Result: protocol.EventsSubscribeResult{SubscriptionID: "fixture-events-subscription", Cursors: []protocol.EventSubscriptionCursor{}},
						Replay: events,
					}, nil
				},
			},
		},
		Runtime: provider.RuntimeHandlers{
			Sessions: provider.RuntimeSessionHandlers{
				Create: func(context.Context, provider.MutationMeta, protocol.RuntimeCreateSessionRequest) (protocol.RuntimeSessionResult, error) {
					return fixtureSessionResult(manifest.ID, calls.Add(1), protocol.LifecycleRunning), nil
				},
				Stop: func(context.Context, provider.MutationMeta, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
					return fixtureSessionResult(manifest.ID, calls.Add(1), protocol.LifecycleStopped), nil
				},
				Terminate: func(context.Context, provider.MutationMeta, protocol.RuntimeSessionRequest) (protocol.RuntimeSessionResult, error) {
					return fixtureSessionResult(manifest.ID, calls.Add(1), protocol.LifecycleTerminated), nil
				},
			},
			Terminal: provider.TerminalHandlers{
				Subscribe: func(_ context.Context, request protocol.TerminalSubscribeRequest) (provider.TerminalSubscription, error) {
					data := "fixture-output"
					if uint64(len(data)) > request.WindowBytes {
						data = data[:request.WindowBytes]
					}
					return provider.TerminalSubscription{
						Result: protocol.EventsSubscribeResult{SubscriptionID: "fixture-terminal-subscription", Cursors: []protocol.EventSubscriptionCursor{}},
						Replay: []protocol.TerminalChunk{{
							NativeSessionID: request.NativeSessionID,
							StreamID:        request.StreamID,
							Encoding:        protocol.TerminalEncodingUTF8,
							Sequence:        1,
							Offset:          request.AfterOffset,
							ObservedAt:      time.Now().UTC(),
							Data:            data,
							Replayed:        true,
							Redactions:      []protocol.TerminalRedaction{},
							CreditRemaining: request.WindowBytes - uint64(len(data)),
						}},
					}, nil
				},
			},
		},
	}
	server, err := provider.NewServer(
		provider.ServerConfig{Manifest: manifest, AuthenticationModes: []string{"none"}, ReplaySupported: true},
		handlers,
		provider.WithLimits(provider.TestLimits()),
	)
	if err != nil {
		return 3
	}
	if err := server.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		return 4
	}
	return 0
}

func fixtureManifest() protocol.ProviderManifest {
	names := []protocol.CapabilityName{
		"provider.initialize",
		"provider.health",
		"provider.capabilities",
		"command.get_result",
		"events.subscribe",
		"runtime.create_session",
		"runtime.stop_session",
		"runtime.terminate_session",
		"terminal.subscribe",
	}
	capabilities := make([]protocol.CapabilityDescriptor, 0, len(names))
	for _, name := range names {
		descriptor, ok := protocol.Capability(name)
		if !ok {
			panic("fixture capability is unknown")
		}
		capabilities = append(capabilities, descriptor)
	}
	return protocol.ProviderManifest{
		ProtocolVersion:     protocol.Version,
		ID:                  "conformance-external-provider",
		Roles:               []protocol.ProviderRole{protocol.RoleSessionRuntime},
		Name:                "Conformance External Provider",
		Version:             "1.0.0",
		Executable:          "conformance-external-provider",
		Platforms:           []protocol.Platform{{OS: runtime.GOOS, Architecture: runtime.GOARCH}},
		Capabilities:        capabilities,
		InteractionModes:    []string{"json-rpc"},
		Permissions:         []string{},
		ConfigurationSchema: "schema.json",
		Extensions:          map[string]json.RawMessage{},
	}
}

func fixtureSessionResult(providerID string, sequence uint64, lifecycle protocol.State) protocol.RuntimeSessionResult {
	return protocol.RuntimeSessionResult{Session: protocol.RuntimeSession{
		ProviderID:      providerID,
		NativeSessionID: "fixture-native-session",
		Lifecycle:       fixtureState(protocol.AxisLifecycle, lifecycle, sequence),
		Health:          fixtureState(protocol.AxisHealth, protocol.HealthHealthy, sequence),
		Extensions:      map[string]json.RawMessage{},
	}}
}

func fixtureState(axis protocol.StateAxis, state protocol.State, sequence uint64) protocol.StateReport {
	return protocol.StateReport{
		Axis:       axis,
		State:      state,
		Source:     "conformance-fixture",
		ObservedAt: time.Now().UTC(),
		Sequence:   sequence,
		Confidence: 1,
		Authority:  protocol.AuthorityAuthoritative,
	}
}

func fixtureEvents(providerID string) []protocol.ProviderEvent {
	one := fixtureEvent(providerID, "fixture-event-one", 1)
	return []protocol.ProviderEvent{
		one,
		one,
		fixtureEvent(providerID, "fixture-event-three", 3),
		fixtureEvent(providerID, "fixture-event-two", 2),
	}
}

func fixtureEvent(providerID, id string, sequence uint64) protocol.ProviderEvent {
	return protocol.ProviderEvent{
		ProtocolVersion: protocol.Version,
		EventID:         id,
		ProviderID:      providerID,
		Role:            protocol.RoleSessionRuntime,
		StreamID:        "fixture-event-stream",
		Type:            "example.conformance/event",
		Sequence:        sequence,
		ObservedAt:      time.Now().UTC(),
		Payload:         json.RawMessage(`{}`),
		Extensions:      map[string]json.RawMessage{},
	}
}
