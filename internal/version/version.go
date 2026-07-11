// Package version exposes the edge build identity and supported provider
// protocol range.
package version

const SupportedProtocolRange = "mission-control.provider.v1alpha1"

// These values are replaced at build time with -ldflags -X.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

// Info is the version information reported by an edge build.
type Info struct {
	Version       string
	Commit        string
	Date          string
	ProtocolRange string
}

// Current returns the version information for this build.
func Current() Info {
	return Info{
		Version:       Version,
		Commit:        Commit,
		Date:          Date,
		ProtocolRange: SupportedProtocolRange,
	}
}
