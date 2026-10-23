package main

import (
	"runtime/debug"
)

// version can be overridden with -ldflags "-X main.version=...". When it
// is empty, the version is read from the build info embedded by the Go
// toolchain, which also works for `go install`.
var version string

const develVersion = "(devel)"

func getVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		return versionFromBuildInfo(info)
	}
	return "(unset)"
}

func versionFromBuildInfo(info *debug.BuildInfo) string {
	if info.Main.Version != "" && info.Main.Version != develVersion {
		return info.Main.Version
	}
	if v, ok := vcsVersion(info); ok {
		return v
	}
	return "(unset)"
}

// vcsVersion builds "devel-<revision>[-dirty] (<commit time>)" from the
// VCS settings stamped by `go build` inside a checkout.
func vcsVersion(info *debug.BuildInfo) (string, bool) {
	const shortRevision = 12
	var revision, commitTime string
	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			commitTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "", false
	}
	v := "devel-" + revision[:min(len(revision), shortRevision)]
	if modified {
		v += "-dirty"
	}
	if commitTime != "" {
		v += " (" + commitTime + ")"
	}
	return v, true
}
