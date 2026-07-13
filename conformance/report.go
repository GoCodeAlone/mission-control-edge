package conformance

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const ReportSchemaVersion = "mission-control.conformance.report.v1alpha1"

type Status string

const (
	StatusPassed  Status = "passed"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

type CaseResult struct {
	ID             string                  `json:"id"`
	Description    string                  `json:"description"`
	Capability     protocol.CapabilityName `json:"capability,omitempty"`
	Required       bool                    `json:"required"`
	Status         Status                  `json:"status"`
	DurationMillis int64                   `json:"duration_ms"`
	ErrorCode      protocol.ErrorCode      `json:"error_code,omitempty"`
	Summary        string                  `json:"summary,omitempty"`
}

type Report struct {
	SchemaVersion   string                               `json:"schema_version"`
	SuiteVersion    string                               `json:"suite_version"`
	ProviderID      string                               `json:"provider_id,omitempty"`
	ProviderVersion string                               `json:"provider_version,omitempty"`
	ProtocolVersion string                               `json:"protocol_version,omitempty"`
	StartedAt       time.Time                            `json:"started_at"`
	FinishedAt      time.Time                            `json:"finished_at"`
	Results         []CaseResult                         `json:"results"`
	CapabilityCases map[protocol.CapabilityName][]string `json:"capability_cases"`
}

func (r Report) HasRequiredFailures() bool {
	for _, result := range r.Results {
		if result.Required && result.Status == StatusFailed {
			return true
		}
	}
	return false
}

func (r Report) Result(id string) CaseResult {
	for _, result := range r.Results {
		if result.ID == id {
			return result
		}
	}
	return CaseResult{}
}

func WriteJSON(writer io.Writer, report Report) error {
	if writer == nil {
		return fmt.Errorf("JSON report writer is required")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode JSON conformance report: %w", err)
	}
	return nil
}

func WriteJUnit(writer io.Writer, report Report) error {
	if writer == nil {
		return fmt.Errorf("JUnit report writer is required")
	}
	suite := junitSuite{
		Name:      "mission-control-provider-conformance",
		Tests:     len(report.Results),
		Timestamp: report.StartedAt.UTC().Format(time.RFC3339Nano),
		Time:      seconds(report.FinishedAt.Sub(report.StartedAt)),
	}
	results := append([]CaseResult(nil), report.Results...)
	slices.SortFunc(results, func(left, right CaseResult) int { return compareStrings(left.ID, right.ID) })
	for _, result := range results {
		entry := junitCase{
			Name:      result.Description,
			Classname: result.ID,
			Time:      seconds(time.Duration(result.DurationMillis) * time.Millisecond),
		}
		switch result.Status {
		case StatusFailed:
			suite.Failures++
			entry.Failure = &junitFailure{Message: result.Summary, Type: string(result.ErrorCode)}
		case StatusSkipped:
			suite.Skipped++
			entry.Skipped = &junitSkipped{Message: result.Summary}
		}
		suite.Cases = append(suite.Cases, entry)
	}
	if _, err := io.WriteString(writer, xml.Header); err != nil {
		return fmt.Errorf("write JUnit header: %w", err)
	}
	encoder := xml.NewEncoder(writer)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suite); err != nil {
		return fmt.Errorf("encode JUnit conformance report: %w", err)
	}
	if _, err := io.WriteString(writer, "\n"); err != nil {
		return fmt.Errorf("finish JUnit report: %w", err)
	}
	return nil
}

type junitSuite struct {
	XMLName   xml.Name    `xml:"testsuite"`
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Skipped   int         `xml:"skipped,attr"`
	Timestamp string      `xml:"timestamp,attr,omitempty"`
	Time      string      `xml:"time,attr"`
	Cases     []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr,omitempty"`
	Type    string `xml:"type,attr,omitempty"`
}

type junitSkipped struct {
	Message string `xml:"message,attr,omitempty"`
}

func seconds(duration time.Duration) string {
	if duration < 0 {
		duration = 0
	}
	return strconv.FormatFloat(duration.Seconds(), 'f', 3, 64)
}

func compareStrings(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}
