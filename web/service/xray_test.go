package service

import "testing"

func TestNormalizeRealitySettings(t *testing.T) {
	stream := map[string]any{
		"realitySettings": map[string]any{
			"target":      "www.nvidia.com:443",
			"maxTimediff": float64(1000),
			"settings":    map[string]any{"publicKey": "client-only"},
		},
	}

	normalizeRealitySettings(stream)

	reality := stream["realitySettings"].(map[string]any)
	if reality["dest"] != "www.nvidia.com:443" {
		t.Fatalf("dest not migrated: %#v", reality)
	}
	if reality["maxTimeDiff"] != float64(1000) {
		t.Fatalf("maxTimeDiff not migrated: %#v", reality)
	}
	if _, ok := reality["target"]; ok {
		t.Fatalf("target should not reach xray config: %#v", reality)
	}
	if _, ok := reality["settings"]; ok {
		t.Fatalf("client-only settings should not reach xray config: %#v", reality)
	}
}
