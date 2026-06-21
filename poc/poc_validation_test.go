package poc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPoCUsesTargetValidationWithRevocation(t *testing.T) {
	var goFiles []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range goFiles {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if strings.Contains(src, "ValidateJWSWithPresentations") {
			t.Fatalf("%s still calls legacy ValidateJWSWithPresentations", path)
		}
		if strings.Contains(src, "ValidatePACT(") {
			for _, required := range []string{
				"RequireRevocation:    true",
				"RevocationCheckpoint: rc",
				"TrustedIssuerPK:      pocconfig.RevocationIssuerPublicKey()",
			} {
				if !strings.Contains(src, required) {
					t.Fatalf("%s calls ValidatePACT without strict RC_e option %q", path, required)
				}
			}
		}
	}
}
