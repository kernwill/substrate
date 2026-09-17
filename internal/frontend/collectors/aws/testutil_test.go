package aws

import (
	"encoding/json"
	"os"
	"testing"
)

// readTestdataJSON reads testdata/<name> and unmarshals it into v,
// failing the test loudly on either error. Shared by every fixture
// loader in this package (loadFakeS3, loadFakeIAM, and whatever the
// next collector's test file adds) rather than each defining its own
// copy of the same ten lines.
func readTestdataJSON(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse testdata/%s: %v", name, err)
	}
}
