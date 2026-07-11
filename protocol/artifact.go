package protocol

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

type ArtifactCreatorType string

const (
	ArtifactCreatorAgent    ArtifactCreatorType = "agent"
	ArtifactCreatorHuman    ArtifactCreatorType = "human"
	ArtifactCreatorWorkflow ArtifactCreatorType = "workflow"
	ArtifactCreatorSystem   ArtifactCreatorType = "system"
)

func (t ArtifactCreatorType) Validate() error {
	switch t {
	case ArtifactCreatorAgent, ArtifactCreatorHuman, ArtifactCreatorWorkflow, ArtifactCreatorSystem:
		return nil
	default:
		return fmt.Errorf("artifact creator type is unsupported")
	}
}

type ArtifactReviewState string

const (
	ArtifactReviewPending  ArtifactReviewState = "pending"
	ArtifactReviewApproved ArtifactReviewState = "approved"
	ArtifactReviewRejected ArtifactReviewState = "rejected"
)

func (s ArtifactReviewState) Validate() error {
	switch s {
	case ArtifactReviewPending, ArtifactReviewApproved, ArtifactReviewRejected:
		return nil
	default:
		return fmt.Errorf("artifact review state is unsupported")
	}
}

type ArtifactLocality string

const (
	ArtifactLocalOnly      ArtifactLocality = "local-only"
	ArtifactUploadEligible ArtifactLocality = "upload-eligible"
	ArtifactHosted         ArtifactLocality = "hosted"
)

func (l ArtifactLocality) Validate() error {
	switch l {
	case ArtifactLocalOnly, ArtifactUploadEligible, ArtifactHosted:
		return nil
	default:
		return fmt.Errorf("artifact locality is unsupported")
	}
}

type Artifact struct {
	ProtocolVersion string                     `json:"protocol_version"`
	ArtifactID      string                     `json:"artifact_id"`
	SessionID       string                     `json:"session_id"`
	CreatorType     ArtifactCreatorType        `json:"creator_type"`
	CreatorID       string                     `json:"creator_id"`
	Version         string                     `json:"version"`
	ReviewState     ArtifactReviewState        `json:"review_state"`
	Locality        ArtifactLocality           `json:"locality"`
	Locator         string                     `json:"locator"`
	MIMEType        string                     `json:"mime_type"`
	Size            int64                      `json:"size"`
	Digest          Digest                     `json:"digest"`
	Classification  Sensitivity                `json:"classification"`
	SourceResources []string                   `json:"source_resources"`
	Extensions      map[string]json.RawMessage `json:"extensions"`
}

func (a Artifact) Validate() error {
	if err := validateProtocol(a.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{"artifact_id": a.ArtifactID, "session_id": a.SessionID, "creator_id": a.CreatorID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := a.CreatorType.Validate(); err != nil {
		return err
	}
	if err := validateVersion("version", a.Version); err != nil {
		return err
	}
	if err := a.ReviewState.Validate(); err != nil {
		return err
	}
	if err := validateArtifactLocator(a.Locality, a.Locator); err != nil {
		return err
	}
	if err := validateText("artifact MIME type", a.MIMEType, 256); err != nil {
		return err
	}
	if a.Size < 0 {
		return fmt.Errorf("artifact size is invalid")
	}
	if err := a.Digest.Validate(); err != nil {
		return err
	}
	if err := a.Classification.Validate(); err != nil {
		return err
	}
	if len(a.SourceResources) > 256 {
		return fmt.Errorf("too many artifact source resources")
	}
	if err := validateUniqueStrings("source_resources", a.SourceResources); err != nil {
		return err
	}
	for _, resource := range a.SourceResources {
		if err := validateID("source_resource", resource); err != nil {
			return err
		}
	}
	return validateExtensions(a.Extensions)
}

// ProviderArtifactReport is untrusted provider-local evidence. The gateway may
// use it to construct an Artifact, but the report intentionally has no canonical
// session, creator, classification, or review-authority fields.
type ProviderArtifactReport struct {
	ProtocolVersion  string                     `json:"protocol_version"`
	ReportID         string                     `json:"report_id"`
	ProviderID       string                     `json:"provider_id"`
	Role             ProviderRole               `json:"role"`
	StreamID         string                     `json:"stream_id"`
	NativeSessionID  NativeID                   `json:"native_session_id,omitempty"`
	NativeArtifactID NativeID                   `json:"native_artifact_id"`
	Version          string                     `json:"version"`
	Locality         ArtifactLocality           `json:"locality"`
	Locator          string                     `json:"locator"`
	MIMEType         string                     `json:"mime_type"`
	Size             int64                      `json:"size"`
	Digest           Digest                     `json:"digest"`
	SourceLocators   []string                   `json:"source_locators"`
	Extensions       map[string]json.RawMessage `json:"extensions"`
}

func (r ProviderArtifactReport) Validate() error {
	if err := validateProtocol(r.ProtocolVersion); err != nil {
		return err
	}
	for field, value := range map[string]string{"report_id": r.ReportID, "provider_id": r.ProviderID, "stream_id": r.StreamID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := r.Role.validateConcern(); err != nil {
		return err
	}
	if r.NativeSessionID != "" {
		if err := r.NativeSessionID.Validate(); err != nil {
			return err
		}
	}
	if err := r.NativeArtifactID.Validate(); err != nil {
		return err
	}
	if err := validateVersion("version", r.Version); err != nil {
		return err
	}
	if r.Locality != ArtifactLocalOnly && r.Locality != ArtifactUploadEligible {
		return fmt.Errorf("provider artifact locality is unsupported")
	}
	if err := validateArtifactLocator(r.Locality, r.Locator); err != nil {
		return err
	}
	if err := validateText("artifact MIME type", r.MIMEType, 256); err != nil {
		return err
	}
	if r.Size < 0 {
		return fmt.Errorf("artifact size is invalid")
	}
	if err := r.Digest.Validate(); err != nil {
		return err
	}
	if len(r.SourceLocators) > 256 {
		return fmt.Errorf("too many artifact source locators")
	}
	if err := validateUniqueStrings("source_locators", r.SourceLocators); err != nil {
		return err
	}
	for _, locator := range r.SourceLocators {
		if err := validateArtifactLocator(ArtifactLocalOnly, locator); err != nil {
			return fmt.Errorf("artifact source locator is invalid")
		}
	}
	if err := rejectReservedExtensions(r.Extensions); err != nil {
		return err
	}
	return validateExtensions(r.Extensions)
}

func validateArtifactLocator(locality ArtifactLocality, locator string) error {
	if err := locality.Validate(); err != nil {
		return err
	}
	if len(locator) == 0 || len(locator) > 2048 || strings.ContainsAny(locator, "\\\x00\r\n") {
		return fmt.Errorf("artifact locator is invalid")
	}
	parsed, err := url.Parse(locator)
	if err != nil || parsed.User != nil || parsed.Host == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("artifact locator is invalid")
	}
	expectedScheme := "local-resource"
	if locality == ArtifactHosted {
		expectedScheme = "artifact"
	}
	if parsed.Scheme != expectedScheme {
		return fmt.Errorf("artifact locator scheme does not match locality")
	}
	if err := validateID("artifact locator authority", parsed.Host); err != nil {
		return fmt.Errorf("artifact locator is invalid")
	}
	token := strings.TrimPrefix(parsed.Path, "/")
	if token == parsed.Path || token == "" || strings.Contains(token, "/") {
		return fmt.Errorf("artifact locator must contain exactly one opaque token")
	}
	if err := validateID("artifact locator token", token); err != nil {
		return fmt.Errorf("artifact locator token is invalid")
	}
	return nil
}

type ArtifactListRequest struct {
	NativeSessionID NativeID `json:"native_session_id"`
}

func (r ArtifactListRequest) Validate() error { return r.NativeSessionID.Validate() }

type ArtifactListResult struct {
	Artifacts []ProviderArtifactReport `json:"artifacts"`
}

func (r ArtifactListResult) Validate() error {
	if len(r.Artifacts) > 4096 {
		return fmt.Errorf("too many provider artifacts")
	}
	seen := make(map[NativeID]struct{}, len(r.Artifacts))
	for _, artifact := range r.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[artifact.NativeArtifactID]; duplicate {
			return fmt.Errorf("provider artifact is duplicated")
		}
		seen[artifact.NativeArtifactID] = struct{}{}
	}
	return nil
}

type ArtifactRegisterRequest struct {
	Artifact ProviderArtifactReport `json:"artifact"`
}

func (r ArtifactRegisterRequest) Validate() error { return r.Artifact.Validate() }

type ArtifactRegisterResult struct {
	Operation OperationResult `json:"operation"`
}

func (r ArtifactRegisterResult) Validate() error { return r.Operation.Validate() }
