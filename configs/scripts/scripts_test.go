package scripts_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func scriptDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Dir(filename)
}

func loadScript(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(scriptDir(), name))
	if err != nil {
		t.Fatalf("failed to read script %s: %v", name, err)
	}
	return string(data)
}
