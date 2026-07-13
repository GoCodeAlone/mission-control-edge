package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/GoCodeAlone/mission-control-edge/mock"
	"github.com/GoCodeAlone/mission-control-edge/protocol"
	"github.com/GoCodeAlone/mission-control-edge/provider"
)

const (
	defaultCaseTimeout = 15 * time.Second
	stderrLimit        = 64 << 10
	negotiatedMaximum  = 64 << 10
	redactionMarker    = "mc-conformance-secret-marker"
)

// FaultPlan supplies deterministic byte-boundary faults for a case. The
// provider remains an external process and all protocol behavior remains owned
// by the production SDK on each side of the mock gateway.
type FaultPlan func(Case) (*mock.Faults, error)

type RunnerConfig struct {
	ProviderCommand []string
	Environment     []string
	Directory       string
	Matrix          Matrix
	CaseTimeout     time.Duration
	FaultPlan       FaultPlan
}

func Run(ctx context.Context, config RunnerConfig) (Report, error) {
	if ctx == nil {
		return Report{}, fmt.Errorf("conformance context is required")
	}
	if len(config.ProviderCommand) == 0 || strings.TrimSpace(config.ProviderCommand[0]) == "" {
		return Report{}, fmt.Errorf("external provider command is required")
	}
	for _, argument := range config.ProviderCommand {
		if strings.IndexByte(argument, 0) >= 0 {
			return Report{}, fmt.Errorf("external provider command contains NUL")
		}
	}
	for _, value := range config.Environment {
		if strings.IndexByte(value, 0) >= 0 || !strings.Contains(value, "=") {
			return Report{}, fmt.Errorf("external provider environment is invalid")
		}
	}
	matrix := config.Matrix
	if matrix.SchemaVersion == "" && matrix.SuiteVersion == "" && len(matrix.Cases) == 0 {
		var err error
		matrix, err = DefaultMatrix()
		if err != nil {
			return Report{}, err
		}
	}
	if err := matrix.Validate(); err != nil {
		return Report{}, err
	}
	timeout := config.CaseTimeout
	if timeout == 0 {
		timeout = defaultCaseTimeout
	}
	if timeout < 10*time.Millisecond || timeout > 5*time.Minute {
		return Report{}, fmt.Errorf("conformance case timeout is invalid")
	}

	started := time.Now().UTC()
	report := Report{
		SchemaVersion:   ReportSchemaVersion,
		SuiteVersion:    matrix.SuiteVersion,
		StartedAt:       started,
		Results:         make([]CaseResult, 0, len(matrix.Cases)),
		CapabilityCases: map[protocol.CapabilityName][]string{},
	}
	var discovered *protocol.ProviderInitializeResult
	for _, testCase := range matrix.Cases {
		caseStarted := time.Now()
		result := CaseResult{
			ID:          testCase.ID,
			Description: testCase.Description,
			Capability:  testCase.Capability,
			Required:    testCase.Required,
		}
		if discovered != nil && !testCase.appliesTo(discovered.Manifest) {
			result.Status = StatusSkipped
			result.Summary = "capability_not_advertised"
			result.DurationMillis = time.Since(caseStarted).Milliseconds()
			report.Results = append(report.Results, result)
			continue
		}
		caseCtx, cancel := context.WithTimeout(ctx, timeout)
		outcome := runCase(caseCtx, config, testCase)
		cancel()
		if outcome.initialized != nil {
			if discovered == nil {
				copy := *outcome.initialized
				discovered = &copy
				report.ProviderID = copy.Manifest.ID
				report.ProviderVersion = copy.Manifest.Version
				report.ProtocolVersion = copy.ProtocolVersion
			} else if !sameProviderContract(*discovered, *outcome.initialized) {
				outcome.status = StatusFailed
				outcome.code = protocol.CodeInvalidArgument
				outcome.summary = "invalid_protocol_result"
			}
			if outcome.status != StatusFailed && !testCase.appliesTo(outcome.initialized.Manifest) {
				outcome.status = StatusSkipped
				outcome.summary = "capability_not_advertised"
				outcome.code = ""
			}
		}
		result.Status = outcome.status
		result.ErrorCode = outcome.code
		result.Summary = outcome.summary
		if outcome.capability != "" {
			result.Capability = outcome.capability
		}
		result.DurationMillis = time.Since(caseStarted).Milliseconds()
		report.Results = append(report.Results, result)
	}
	if discovered != nil {
		report.CapabilityCases = matrix.CapabilityCaseMap(discovered.Manifest)
	}
	report.FinishedAt = time.Now().UTC()
	return report, nil
}

func sameProviderContract(left, right protocol.ProviderInitializeResult) bool {
	return left.ProtocolVersion == right.ProtocolVersion &&
		left.NativeRuntimeVersion == right.NativeRuntimeVersion &&
		left.ReplaySupported == right.ReplaySupported &&
		left.AuthenticationMode == right.AuthenticationMode &&
		reflect.DeepEqual(left.Manifest, right.Manifest)
}

type caseOutcome struct {
	status      Status
	code        protocol.ErrorCode
	summary     string
	capability  protocol.CapabilityName
	initialized *protocol.ProviderInitializeResult
}

func passed(initialized *protocol.ProviderInitializeResult) caseOutcome {
	return caseOutcome{status: StatusPassed, initialized: initialized}
}

func skipped(initialized *protocol.ProviderInitializeResult, summary string) caseOutcome {
	return caseOutcome{status: StatusSkipped, summary: summary, initialized: initialized}
}

func failed(initialized *protocol.ProviderInitializeResult, err error) caseOutcome {
	code := errorCode(err)
	return caseOutcome{status: StatusFailed, code: code, summary: errorSummary(code), initialized: initialized}
}

func invalidProtocol(initialized *protocol.ProviderInitializeResult) caseOutcome {
	return caseOutcome{
		status: StatusFailed, code: protocol.CodeInvalidArgument,
		summary: "invalid_protocol_result", initialized: initialized,
	}
}

func runCase(ctx context.Context, config RunnerConfig, testCase Case) caseOutcome {
	switch testCase.Kind {
	case CaseNotSupported:
		return runNotSupported(ctx, config)
	case CaseReconnect:
		return runReconnect(ctx, config)
	case CaseCrashRecovery:
		return runCrashRecovery(ctx, config)
	case CaseRedaction:
		return runRedaction(ctx, config, testCase)
	case CaseOversizedFrame:
		return runOversized(ctx, config, testCase)
	}
	session, initialized, err := startInitialized(ctx, config, testCase, negotiatedMaximum, nil)
	if err != nil {
		return failed(nil, err)
	}
	defer session.Close()
	if !testCase.appliesTo(initialized.Manifest) {
		return skipped(&initialized, "capability_not_advertised")
	}
	switch testCase.Kind {
	case CaseInitializeRequired:
		return passed(&initialized)
	case CaseOptionalCapabilities:
		return runOptionalCapability(ctx, session, initialized)
	case CaseCapabilityMapping:
		return runCapabilityMapping(ctx, session, initialized)
	case CaseEventDuplicate, CaseEventOutOfOrder, CaseReplayGap:
		return runEventSequence(ctx, session, initialized, testCase)
	case CaseCancellation:
		return runCancellation(session, initialized)
	case CaseDeadline:
		return runDeadline(ctx, session, initialized)
	case CaseBackpressure:
		return runBackpressure(ctx, session, initialized)
	case CaseDeliveryClass:
		return runDeliveryClass(ctx, session, initialized, testCase.DeliveryClass)
	default:
		return failed(&initialized, fmt.Errorf("unsupported conformance case"))
	}
}

type processSession struct {
	process *mock.Provider
	gateway *mock.Gateway
	client  *provider.Client
	stderr  *boundedBuffer
}

func startInitialized(
	ctx context.Context,
	config RunnerConfig,
	testCase Case,
	maximum uint64,
	extraEnvironment []string,
) (*processSession, protocol.ProviderInitializeResult, error) {
	session, err := startSession(ctx, config, testCase, extraEnvironment)
	if err != nil {
		return nil, protocol.ProviderInitializeResult{}, err
	}
	initialized, err := session.client.Initialize(ctx, initializeRequest(maximum, nil, nil))
	if err != nil {
		session.Close()
		return nil, protocol.ProviderInitializeResult{}, err
	}
	return session, initialized, nil
}

func startSession(ctx context.Context, config RunnerConfig, testCase Case, extraEnvironment []string) (*processSession, error) {
	var faults *mock.Faults
	var err error
	if config.FaultPlan != nil {
		faults, err = config.FaultPlan(testCase)
		if err != nil {
			return nil, fmt.Errorf("conformance fault plan is invalid")
		}
	}
	diagnostics := &boundedBuffer{maximum: stderrLimit}
	process, err := mock.StartProvider(ctx, mock.ProviderConfig{
		Path:   config.ProviderCommand[0],
		Args:   append([]string(nil), config.ProviderCommand[1:]...),
		Env:    append(append([]string(nil), config.Environment...), extraEnvironment...),
		Dir:    config.Directory,
		Stderr: diagnostics,
	})
	if err != nil {
		return nil, err
	}
	gateway, err := mock.NewGateway(process, faults)
	if err != nil {
		_ = process.Close()
		return nil, err
	}
	client, err := gateway.Client(provider.WithLimits(provider.TestLimits()))
	if err != nil {
		_ = gateway.Close()
		return nil, err
	}
	return &processSession{process: process, gateway: gateway, client: client, stderr: diagnostics}, nil
}

func (s *processSession) Close() {
	if s == nil {
		return
	}
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.gateway != nil {
		_ = s.gateway.Close()
	}
	if s.process != nil {
		_ = s.process.Close()
	}
}

func initializeRequest(maximum uint64, required []protocol.CapabilityName, features []string) protocol.ProviderInitializeRequest {
	if maximum == 0 {
		maximum = negotiatedMaximum
	}
	chunkMaximum := min(maximum, uint64(protocol.MaxTerminalChunkBytes))
	if required == nil {
		required = []protocol.CapabilityName{"provider.initialize", "provider.capabilities"}
	}
	return protocol.ProviderInitializeRequest{
		SupportedProtocolVersions: []string{protocol.Version},
		GatewayVersion:            "0.1.0",
		Platform:                  protocol.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		RequiredCapabilities:      append([]protocol.CapabilityName(nil), required...),
		MaximumMessageBytes:       maximum,
		MaximumChunkBytes:         chunkMaximum,
		ReplaySupported:           true,
		AuthenticationModes:       []string{"none"},
		ExperimentalFeatures:      append([]string{}, features...),
	}
}

func runOptionalCapability(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult) caseOutcome {
	_, advertised := initialized.Manifest.Capability("provider.health")
	_, err := session.client.Health(ctx)
	if advertised {
		if err != nil {
			return failed(&initialized, err)
		}
		return passed(&initialized)
	}
	var structured *protocol.Error
	if !errors.As(err, &structured) || structured.Code != protocol.CodeNotSupported || structured.RequiredCapability != "provider.health" {
		return failed(&initialized, fmt.Errorf("optional capability did not return not_supported"))
	}
	return passed(&initialized)
}

func runCapabilityMapping(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult) caseOutcome {
	capabilities, err := session.client.Capabilities(ctx)
	if err != nil {
		return failed(&initialized, err)
	}
	if capabilities.ProviderID != initialized.Manifest.ID ||
		!reflect.DeepEqual(capabilities.Roles, initialized.Manifest.Roles) ||
		!reflect.DeepEqual(capabilities.Capabilities, initialized.Manifest.Capabilities) {
		return failed(&initialized, fmt.Errorf("capability result does not match manifest"))
	}
	return passed(&initialized)
}

func runNotSupported(ctx context.Context, config RunnerConfig) caseOutcome {
	baseline, initialized, err := startInitialized(ctx, config, Case{Kind: CaseNotSupported}, negotiatedMaximum, nil)
	if err != nil {
		return failed(nil, err)
	}
	baseline.Close()
	unsupported := unsupportedCapability(initialized.Manifest)
	required := []protocol.CapabilityName{"provider.initialize", "provider.capabilities", unsupported}
	session, err := startSession(ctx, config, Case{Kind: CaseNotSupported}, nil)
	if err != nil {
		return failed(&initialized, err)
	}
	defer session.Close()
	_, err = session.client.Initialize(ctx, initializeRequest(negotiatedMaximum, required, nil))
	var structured *protocol.Error
	if !errors.As(err, &structured) || structured.Code != protocol.CodeNotSupported || structured.RequiredCapability != unsupported {
		return failed(&initialized, fmt.Errorf("provider did not return structured not_supported"))
	}
	want := capabilityNames(initialized.Manifest)
	got := append([]protocol.CapabilityName(nil), structured.AdvertisedCapabilities...)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		return failed(&initialized, fmt.Errorf("not_supported capability inventory mismatch"))
	}
	return passed(&initialized)
}

func unsupportedCapability(manifest protocol.ProviderManifest) protocol.CapabilityName {
	for suffix := 0; suffix <= len(manifest.Capabilities); suffix++ {
		candidate := protocol.CapabilityName("example.conformance/unsupported")
		if suffix > 0 {
			candidate = protocol.CapabilityName(fmt.Sprintf("example.conformance/unsupported-%d", suffix))
		}
		if !manifest.Supports(candidate) {
			return candidate
		}
	}
	panic("finite provider capability set exhausted an infinite probe namespace")
}

func runReconnect(ctx context.Context, config RunnerConfig) caseOutcome {
	var first protocol.ProviderInitializeResult
	for attempt := 0; attempt < 2; attempt++ {
		session, initialized, err := startInitialized(ctx, config, Case{Kind: CaseReconnect}, negotiatedMaximum, nil)
		if err != nil {
			return failed(nil, err)
		}
		session.Close()
		if attempt == 0 {
			first = initialized
		} else if !sameProviderContract(first, initialized) {
			return invalidProtocol(&first)
		}
	}
	return passed(&first)
}

func runCrashRecovery(ctx context.Context, config RunnerConfig) caseOutcome {
	first, initialized, err := startInitialized(ctx, config, Case{Kind: CaseCrashRecovery}, negotiatedMaximum, nil)
	if err != nil {
		return failed(nil, err)
	}
	_ = first.process.Crash()
	probeCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	_, probeErr := first.client.Capabilities(probeCtx)
	cancel()
	first.Close()
	if probeErr == nil {
		return failed(&initialized, fmt.Errorf("crashed provider remained available"))
	}
	second, recovered, err := startInitialized(ctx, config, Case{Kind: CaseCrashRecovery}, negotiatedMaximum, nil)
	if err != nil {
		return failed(&initialized, err)
	}
	second.Close()
	if !sameProviderContract(initialized, recovered) {
		return invalidProtocol(&initialized)
	}
	return passed(&initialized)
}

func runCancellation(session *processSession, initialized protocol.ProviderInitializeResult) caseOutcome {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.client.Capabilities(cancelled)
	if !protocol.IsCode(err, protocol.CodeCancelled) {
		return failed(&initialized, fmt.Errorf("cancellation was not structured"))
	}
	return passed(&initialized)
}

func runDeadline(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult) caseOutcome {
	target, ok := commandTargetForDeadline(initialized.Manifest)
	if !ok {
		return skipped(&initialized, "no_supported_deadline_target")
	}
	command := target.command("conformance-deadline-command", time.Now().UTC().Add(-time.Second))
	var result json.RawMessage
	err := session.client.Mutate(ctx, command, &result)
	if !protocol.IsCode(err, protocol.CodeDeadlineExceeded) {
		outcome := failed(&initialized, fmt.Errorf("expired command was not rejected"))
		outcome.capability = target.capability
		return outcome
	}
	outcome := passed(&initialized)
	outcome.capability = target.capability
	return outcome
}

func runDeliveryClass(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult, class protocol.DeliveryClass) caseOutcome {
	target, ok := commandTargetForDelivery(initialized.Manifest, class)
	if !ok {
		return skipped(&initialized, "no_safe_delivery_target")
	}
	command := target.command("conformance-delivery-command-"+string(class), time.Now().UTC().Add(time.Minute))
	var first, second json.RawMessage
	if err := session.client.Mutate(ctx, command, &first); err != nil {
		outcome := failed(&initialized, err)
		outcome.capability = target.capability
		return outcome
	}
	if err := session.client.Mutate(ctx, command, &second); err != nil {
		outcome := failed(&initialized, err)
		outcome.capability = target.capability
		return outcome
	}
	if !bytes.Equal(first, second) {
		outcome := failed(&initialized, fmt.Errorf("exact retry produced a different result"))
		outcome.capability = target.capability
		return outcome
	}
	outcome := passed(&initialized)
	outcome.capability = target.capability
	return outcome
}

func runBackpressure(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult) caseOutcome {
	request := protocol.TerminalSubscribeRequest{
		NativeSessionID: "conformance-native-session",
		StreamID:        "stdout",
		AfterOffset:     0,
		WindowBytes:     4,
	}
	if _, err := session.client.SubscribeTerminal(ctx, request); err != nil {
		return failed(&initialized, err)
	}
	for {
		select {
		case notification, open := <-session.client.Notifications():
			if !open {
				return failed(&initialized, fmt.Errorf("terminal subscription disconnected"))
			}
			if notification.TerminalChunk == nil {
				continue
			}
			chunk := *notification.TerminalChunk
			size, err := terminalSize(chunk.Encoding, chunk.Data)
			if err != nil || size > request.WindowBytes || chunk.CreditRemaining != request.WindowBytes-size {
				return failed(&initialized, fmt.Errorf("terminal output violated credit window"))
			}
			credit := protocol.TerminalCredit{
				NativeSessionID: chunk.NativeSessionID,
				StreamID:        chunk.StreamID,
				Bytes:           size,
				ThroughOffset:   chunk.Offset + size,
			}
			if err := session.client.SendTerminalCredit(ctx, credit); err != nil {
				return failed(&initialized, err)
			}
			return passed(&initialized)
		case <-ctx.Done():
			return skipped(&initialized, "terminal_output_not_observed")
		}
	}
}

func runEventSequence(ctx context.Context, session *processSession, initialized protocol.ProviderInitializeResult, testCase Case) caseOutcome {
	if testCase.RequiresReplay && !initialized.ReplaySupported {
		return skipped(&initialized, "replay_not_supported")
	}
	request := protocol.EventsSubscribeRequest{Cursors: []protocol.EventSubscriptionCursor{}, EventTypes: []string{}, WindowSize: 16}
	var subscription protocol.EventsSubscribeResult
	if err := session.client.Query(ctx, "events.subscribe", request, &subscription); err != nil {
		return failed(&initialized, err)
	}
	tracker := protocol.NewSequenceTracker()
	var highest uint64
	observed := false
	for !observed {
		select {
		case notification, open := <-session.client.Notifications():
			if !open {
				return failed(&initialized, fmt.Errorf("event subscription disconnected"))
			}
			if notification.Event == nil {
				continue
			}
			event := *notification.Event
			outcome, err := tracker.Observe(protocol.EventCursor{
				ProviderID: event.ProviderID,
				Role:       event.Role,
				StreamID:   event.StreamID,
				EventID:    event.EventID,
				Sequence:   event.Sequence,
				Digest:     providerEventDigest(event),
			})
			if err != nil {
				return failed(&initialized, err)
			}
			switch testCase.Kind {
			case CaseEventDuplicate:
				observed = outcome == protocol.SequenceDuplicate
			case CaseReplayGap:
				observed = outcome == protocol.SequenceGap
			case CaseEventOutOfOrder:
				observed = highest != 0 && event.Sequence < highest
			}
			if event.Sequence > highest {
				highest = event.Sequence
			}
		case <-ctx.Done():
			return skipped(&initialized, "event_pattern_not_observed")
		}
	}
	return passed(&initialized)
}

func runOversized(ctx context.Context, config RunnerConfig, testCase Case) caseOutcome {
	session, initialized, err := startInitialized(ctx, config, testCase, 512, nil)
	if err != nil {
		return failed(nil, err)
	}
	defer session.Close()
	_, err = session.client.Capabilities(ctx)
	if err == nil {
		return passed(&initialized)
	}
	if protocol.IsCode(err, protocol.CodeMessageTooLarge) {
		probe := time.NewTimer(20 * time.Millisecond)
		defer probe.Stop()
		for {
			select {
			case _, open := <-session.client.Notifications():
				if !open {
					return failed(&initialized, fmt.Errorf("oversized response terminated the provider client"))
				}
			case <-probe.C:
				return passed(&initialized)
			case <-ctx.Done():
				return failed(&initialized, ctx.Err())
			}
		}
	}
	return failed(&initialized, err)
}

func runRedaction(ctx context.Context, config RunnerConfig, testCase Case) caseOutcome {
	session, err := startSession(ctx, config, testCase, []string{"MC_CONFORMANCE_SECRET_MARKER=" + redactionMarker})
	if err != nil {
		return failed(nil, err)
	}
	initialized, initializeErr := session.client.Initialize(ctx, initializeRequest(negotiatedMaximum, nil, []string{redactionMarker}))
	session.Close()
	if initializeErr != nil {
		return failed(nil, initializeErr)
	}
	if session.stderr.Overflowed() {
		return caseOutcome{
			status:      StatusFailed,
			code:        protocol.CodeResourceExhausted,
			summary:     "diagnostics_limit_exceeded",
			initialized: &initialized,
		}
	}
	if session.stderr.Contains(redactionMarker) {
		return failed(&initialized, fmt.Errorf("provider diagnostics exposed secret content"))
	}
	return passed(&initialized)
}

type commandTarget struct {
	capability protocol.CapabilityName
	delivery   protocol.DeliveryClass
	sessionID  string
	payload    json.RawMessage
}

func (t commandTarget) command(id string, deadline time.Time) protocol.Command {
	return protocol.Command{
		ProtocolVersion:   protocol.Version,
		CommandID:         id,
		SessionID:         t.sessionID,
		Capability:        t.capability,
		IdempotencyKey:    id + "-idempotency-key",
		CancellationToken: id + "-cancellation-token",
		Deadline:          deadline.UTC(),
		DeliveryClass:     t.delivery,
		Payload:           append(json.RawMessage(nil), t.payload...),
	}
}

func commandTargetForDeadline(manifest protocol.ProviderManifest) (commandTarget, bool) {
	for _, capability := range []protocol.CapabilityName{"runtime.create_session", "runtime.stop_session", "runtime.terminate_session", "provider.shutdown"} {
		if manifest.Supports(capability) {
			return commandTargetForCapability(capability)
		}
	}
	return commandTarget{}, false
}

func commandTargetForDelivery(manifest protocol.ProviderManifest, class protocol.DeliveryClass) (commandTarget, bool) {
	capability, supported := deliveryTargetCapability(manifest, class)
	if !supported {
		return commandTarget{}, false
	}
	return commandTargetForCapability(capability)
}

func commandTargetForCapability(capability protocol.CapabilityName) (commandTarget, bool) {
	descriptor, ok := protocol.Capability(capability)
	if !ok || !descriptor.Mutating {
		return commandTarget{}, false
	}
	target := commandTarget{capability: capability, delivery: descriptor.DeliveryClass}
	switch capability {
	case "provider.shutdown":
		target.payload = json.RawMessage(`{}`)
	case "runtime.create_session":
		configuration := json.RawMessage(`{}`)
		digest := sha256.Sum256(configuration)
		request := protocol.RuntimeCreateSessionRequest{
			NativeEnvironmentID: "conformance-environment",
			Configuration:       configuration,
			ConfigurationDigest: protocol.Digest("sha256:" + hex.EncodeToString(digest[:])),
		}
		target.sessionID = "conformance-session"
		target.payload = mustJSON(request)
	case "runtime.stop_session", "runtime.terminate_session":
		target.sessionID = "conformance-session"
		target.payload = mustJSON(protocol.RuntimeSessionRequest{NativeSessionID: "conformance-native-session"})
	default:
		return commandTarget{}, false
	}
	return target, true
}

func capabilityNames(manifest protocol.ProviderManifest) []protocol.CapabilityName {
	result := make([]protocol.CapabilityName, 0, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		result = append(result, capability.Name)
	}
	return result
}

func providerEventDigest(event protocol.ProviderEvent) protocol.Digest {
	data := mustJSON(event)
	digest := sha256.Sum256(data)
	return protocol.Digest("sha256:" + hex.EncodeToString(digest[:]))
}

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic("conformance static value is not JSON")
	}
	return data
}

func terminalSize(encoding protocol.TerminalEncoding, data string) (uint64, error) {
	switch encoding {
	case protocol.TerminalEncodingUTF8:
		if !utf8.ValidString(data) {
			return 0, fmt.Errorf("terminal data is not UTF-8")
		}
		return uint64(len(data)), nil
	case protocol.TerminalEncodingBase64:
		decoded, err := base64.StdEncoding.Strict().DecodeString(data)
		return uint64(len(decoded)), err
	default:
		return 0, fmt.Errorf("terminal encoding is unsupported")
	}
}

func errorCode(err error) protocol.ErrorCode {
	var structured *protocol.Error
	if errors.As(err, &structured) && structured.Code.Validate() == nil {
		return structured.Code
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return protocol.CodeDeadlineExceeded
	case errors.Is(err, context.Canceled):
		return protocol.CodeCancelled
	default:
		return protocol.CodeUnavailable
	}
}

func errorSummary(code protocol.ErrorCode) string {
	switch code {
	case protocol.CodeInvalidArgument:
		return "invalid_protocol_result"
	case protocol.CodeMessageTooLarge:
		return "message_too_large"
	case protocol.CodeNotSupported:
		return "capability_not_supported"
	case protocol.CodeSequenceConflict:
		return "sequence_conflict"
	case protocol.CodeDeadlineExceeded:
		return "case_deadline_exceeded"
	case protocol.CodeCancelled:
		return "case_cancelled"
	case protocol.CodeResourceExhausted:
		return "resource_exhausted"
	case protocol.CodeOutcomeUnknown:
		return "outcome_unknown"
	default:
		return "provider_unavailable"
	}
}

type boundedBuffer struct {
	mu       sync.Mutex
	maximum  int
	data     []byte
	overflow bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.maximum - len(b.data)
	if remaining > 0 {
		b.data = append(b.data, value[:min(remaining, len(value))]...)
	}
	if len(value) > remaining {
		b.overflow = true
	}
	return len(value), nil
}

func (b *boundedBuffer) Contains(value string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Contains(b.data, []byte(value))
}

func (b *boundedBuffer) Overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

var _ io.Writer = (*boundedBuffer)(nil)
