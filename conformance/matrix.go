package conformance

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

//go:embed testdata/*.json
var matrixFiles embed.FS

type Matrix struct {
	SchemaVersion string `json:"schema_version"`
	SuiteVersion  string `json:"suite_version"`
	Cases         []Case `json:"cases"`
}

func DefaultMatrix() (Matrix, error) {
	file, err := matrixFiles.Open("testdata/cases.v1alpha1.json")
	if err != nil {
		return Matrix{}, fmt.Errorf("open embedded conformance matrix: %w", err)
	}
	defer func() { _ = file.Close() }()
	return LoadMatrix(file)
}

func LoadMatrix(reader io.Reader) (Matrix, error) {
	if reader == nil {
		return Matrix{}, fmt.Errorf("conformance matrix reader is required")
	}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var matrix Matrix
	if err := decoder.Decode(&matrix); err != nil {
		return Matrix{}, fmt.Errorf("decode conformance matrix: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Matrix{}, fmt.Errorf("conformance matrix contains trailing content")
	}
	if err := matrix.Validate(); err != nil {
		return Matrix{}, err
	}
	return matrix, nil
}

func (m Matrix) Validate() error {
	if m.SchemaVersion != CaseSchemaVersion {
		return fmt.Errorf("conformance matrix schema version is unsupported")
	}
	if !validSuiteVersion(m.SuiteVersion) {
		return fmt.Errorf("conformance suite version is invalid")
	}
	if len(m.Cases) == 0 || len(m.Cases) > 1024 {
		return fmt.Errorf("conformance matrix cases are invalid")
	}
	seen := make(map[string]struct{}, len(m.Cases))
	for _, testCase := range m.Cases {
		if err := testCase.Validate(); err != nil {
			return fmt.Errorf("conformance case %q: %w", testCase.ID, err)
		}
		if _, duplicate := seen[testCase.ID]; duplicate {
			return fmt.Errorf("conformance case %q is duplicated", testCase.ID)
		}
		seen[testCase.ID] = struct{}{}
	}
	return nil
}

func (m Matrix) HasKind(kind CaseKind) bool {
	for _, testCase := range m.Cases {
		if testCase.Kind == kind {
			return true
		}
	}
	return false
}

func (m Matrix) HasDeliveryClass(class protocol.DeliveryClass) bool {
	for _, testCase := range m.Cases {
		if testCase.Kind == CaseDeliveryClass && testCase.DeliveryClass == class {
			return true
		}
	}
	return false
}

func (m Matrix) CapabilityCaseMap(manifest protocol.ProviderManifest) map[protocol.CapabilityName][]string {
	result := make(map[protocol.CapabilityName][]string, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		ids := make([]string, 0, 4)
		for _, testCase := range m.Cases {
			deliveryTarget, hasDeliveryTarget := deliveryTargetCapability(manifest, testCase.DeliveryClass)
			switch {
			case testCase.Kind == CaseCapabilityMapping:
				ids = append(ids, testCase.ID)
			case testCase.Capability == capability.Name:
				ids = append(ids, testCase.ID)
			case testCase.Kind == CaseDeliveryClass && hasDeliveryTarget && deliveryTarget == capability.Name:
				ids = append(ids, testCase.ID)
			}
		}
		slices.Sort(ids)
		result[capability.Name] = slices.Compact(ids)
	}
	return result
}

func validSuiteVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
		if len(part) > 1 && part[0] == '0' {
			return false
		}
	}
	return true
}
