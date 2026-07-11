package version

import "testing"

func TestSupportedProtocolRange(t *testing.T) {
	t.Parallel()

	const want = "mission-control.provider.v1alpha1"
	if SupportedProtocolRange != want {
		t.Fatalf("SupportedProtocolRange = %q, want %q", SupportedProtocolRange, want)
	}
}

func TestCurrentUsesInjectedBuildMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate := Version, Commit, Date
	t.Cleanup(func() {
		Version, Commit, Date = originalVersion, originalCommit, originalDate
	})

	Version = "v0.1.0-test"
	Commit = "0123456789abcdef"
	Date = "2026-07-11T00:00:00Z"

	want := Info{
		Version:       Version,
		Commit:        Commit,
		Date:          Date,
		ProtocolRange: SupportedProtocolRange,
	}
	if got := Current(); got != want {
		t.Fatalf("Current() = %#v, want %#v", got, want)
	}
}
