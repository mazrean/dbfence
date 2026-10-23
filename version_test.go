package main

import (
	"runtime/debug"
	"testing"
)

func TestVersionFromBuildInfo(t *testing.T) {
	t.Parallel()
	vcs := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "5a64ce2f1b2c3d4e5f60718293a4b5c6d7e8f901"},
		{Key: "vcs.time", Value: "2026-10-23T12:00:00Z"},
		{Key: "vcs.modified", Value: "true"},
	}
	tests := []struct {
		name string
		info *debug.BuildInfo
		want string
	}{
		{name: "module version from go install", info: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, want: "v1.2.3"},
		{name: "devel with vcs", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs}, want: "devel-5a64ce2f1b2c-dirty (2026-10-23T12:00:00Z)"},
		{name: "clean vcs", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: vcs[:1]}, want: "devel-5a64ce2f1b2c"},
		{name: "nothing", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, want: "(unset)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := versionFromBuildInfo(tt.info); got != tt.want {
				t.Errorf("versionFromBuildInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}
