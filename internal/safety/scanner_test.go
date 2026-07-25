package safety

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTestFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func hasFinding(findings []Finding, path, code string) bool {
	for _, finding := range findings {
		if finding.Path == path && finding.Code == code {
			return true
		}
	}
	return false
}

func TestScannerAllowsOnlyExplicitImportsAndOSSelectors(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "allowed.go", "package sample\nimport \"strings\"\nvar _ = strings.TrimSpace\n")
	writeTestFile(t, root, "nested/network.go", "package nested\nimport h \"net/http\"\nvar _ = h.MethodGet\n")
	writeTestFile(t, root, "nested/write.go", "package nested\nimport operating \"os\"\nfunc write() { _ = operating.WriteFile(\"x\", nil, 0600) }\n")
	writeTestFile(t, root, "nested/write-alias.go", "package nested\nimport operating \"os\"\nvar write = operating.WriteFile\n")
	writeTestFile(t, root, "nested/read.go", "package nested\nimport operating \"os\"\nvar read = operating.ReadFile\n")
	writeTestFile(t, root, "nested/start.go", "package nested\nimport operating \"os\"\nvar start = operating.StartProcess\n")
	writeTestFile(t, root, "nested/find.go", "package nested\nimport operating \"os\"\nvar find = operating.FindProcess\n")
	writeTestFile(t, root, "nested/legal.go", "package safety\nimport \"os\"\nvar read = os.ReadFile\n")
	writeTestFile(t, root, "nested/clock.go", "package nested\nimport \"time\"\nvar now = time.Now\n")
	writeTestFile(t, root, "internal/model/model.go", "package model\nimport \"time\"\nvar parse = time.Parse\n")
	writeTestFile(t, root, "nested/safety.go", "package nested\nimport gate \"github.com/PastureStack/vault-secrets-bridge/internal/safety\"\nvar _ = gate.ScanProductionTree\n")
	writeTestFile(t, root, "cmd/vault-secrets-bridge/main.go", "package main\nimport (\"os\"; \"github.com/PastureStack/vault-secrets-bridge/internal/cli\")\nfunc main() { os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }\n")
	writeTestFile(t, root, "cmd/vault-secrets-bridge/chained.go", "package main\nimport \"os\"\nvar write = os.Stdout.Write\n")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "nested/network.go", "import-not-allowed") {
		t.Fatal("network import was not rejected")
	}
	if !hasFinding(findings, "nested/write.go", "os-selector-not-allowed") {
		t.Fatal("filesystem write call was not rejected")
	}
	if !hasFinding(findings, "nested/write-alias.go", "os-selector-not-allowed") {
		t.Fatal("filesystem write selector alias was not rejected")
	}
	for _, path := range []string{"nested/read.go", "nested/start.go", "nested/find.go", "nested/legal.go"} {
		if !hasFinding(findings, path, "os-selector-not-allowed") || !hasFinding(findings, path, "os-import-not-allowed") {
			t.Fatalf("unapproved os access was not rejected for %s: %v", path, findings)
		}
	}
	if !hasFinding(findings, "nested/safety.go", "safety-package-import-not-allowed") {
		t.Fatal("production import of the filesystem-reading safety package was not rejected")
	}
	if !hasFinding(findings, "nested/clock.go", "time-import-not-allowed") ||
		!hasFinding(findings, "nested/clock.go", "time-selector-not-allowed") {
		t.Fatal("untrusted current-clock access was not rejected")
	}
	if !hasFinding(findings, "cmd/vault-secrets-bridge/chained.go", "os-import-not-allowed") ||
		!hasFinding(findings, "cmd/vault-secrets-bridge/chained.go", "os-selector-chain-not-allowed") {
		t.Fatal("method access through an os value was not rejected")
	}
	for _, finding := range findings {
		if finding.Path == "allowed.go" || finding.Path == "cmd/vault-secrets-bridge/main.go" ||
			finding.Path == "internal/model/model.go" {
			t.Fatalf("allowed source was rejected: %+v", finding)
		}
	}
}

func TestScannerScansGoTestContentButSkipsTestImports(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".git/bad.go", "package hidden\nimport \"net/http\"\n")
	writeTestFile(t, root, "ignored_test.go", "package sample\nimport \"net/http\"\n")
	writeTestFile(t, root, "private_test.go", "package sample\n// personal namespace: chen"+"21019\n")
	writeTestFile(t, root, "nested/.git/bad.go", "package nested\nimport \"net/http\"\n")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Path == ".git/bad.go" || (finding.Path == "ignored_test.go" && finding.Code == "import-not-allowed") {
			t.Fatalf("excluded import was scanned: %+v", finding)
		}
	}
	if !hasFinding(findings, "private_test.go", "private-namespace") {
		t.Fatal("public Go test content was not scanned")
	}
	if !hasFinding(findings, "nested/.git/bad.go", "import-not-allowed") {
		t.Fatal("nested .git directory was incorrectly skipped")
	}
}

func TestScannerFindsPrivateAndLegacyProductionContent(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "private.txt", "personal namespace: chen"+"21019")
	writeTestFile(t, root, "legacy.txt", "module github.com/ran"+"cher/example")
	writeTestFile(t, root, "new-name.txt", "vault-secrets-bridge")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "private.txt", "private-namespace") {
		t.Fatal("private namespace was not rejected")
	}
	if !hasFinding(findings, "legacy.txt", "legacy-implementation") {
		t.Fatal("legacy implementation reference was not rejected")
	}
	for _, finding := range findings {
		if finding.Path == "new-name.txt" {
			t.Fatalf("current binary name was rejected: %+v", finding)
		}
	}
}

func TestLegalAttributionEmailIsAllowedButPrivateNamespaceIsNot(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "LICENSES/historical/dependency-01.txt", "Copyright Example <author"+"@example.org>\n")
	writeTestFile(t, root, "LICENSES/historical/dependency-02.txt", "personal namespace: chen"+"21019\n")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Path == "LICENSES/historical/dependency-01.txt" && finding.Code == "email-address" {
			t.Fatal("exact legal attribution email was rejected")
		}
	}
	if !hasFinding(findings, "LICENSES/historical/dependency-02.txt", "private-namespace") {
		t.Fatal("private namespace was allowed in a legal path")
	}
}

func TestScannerRejectsOldBinaryNameWithoutRejectingCurrentName(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "old.txt", "binary secrets-"+"bridge-v2")
	writeTestFile(t, root, "new.txt", "binary vault-secrets-bridge")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "old.txt", "legacy-implementation") {
		t.Fatal("old binary name was not rejected")
	}
	for _, finding := range findings {
		if finding.Path == "new.txt" {
			t.Fatalf("current name was rejected: %+v", finding)
		}
	}
}

func TestScannerRequiresExactReadmeOpening(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "README.md", "Different opening.\n")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "README.md", "readme-opening") {
		t.Fatal("incorrect README opening was not rejected")
	}
	writeTestFile(t, root, "README.md", RequiredReadmeOpening+"\n\nSafe remainder.\n")
	findings, err = ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("exact README opening was rejected: %v", findings)
	}
	writeTestFile(t, root, "README.md", RequiredReadmeOpening+"\n\nUnexpected Ran"+"cher implementation text.\n")
	findings, err = ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "README.md", "legacy-brand") {
		t.Fatal("brand text outside the fixed disclaimer was not rejected")
	}
}

func TestScannerRejectsSymlinkEntries(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(findings, "link", "symlink-entry") {
		t.Fatal("symlink entry was not rejected")
	}
}

func TestScannerOutputIsDeterministic(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "z.go", "package z\nimport \"net/http\"\n")
	writeTestFile(t, root, "a.txt", "chen"+"21019")
	first, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("scanner findings are not deterministic")
	}
}

func TestScannerRejectsRiskFilesPEMEmailNULBinaryAndNullJSON(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "identity.key", "not a real key")
	writeTestFile(t, root, "mail.txt", "person"+"@example.invalid")
	writeTestFile(t, root, "material.txt", "-----BE"+"GIN "+"PRIVATE "+"KEY-----")
	writeTestFile(t, root, "null.json", `{"value":null}`)
	if err := os.WriteFile(filepath.Join(root, "nul.txt"), []byte{'a', 0, 'b'}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "binary.dat"), []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	checks := []Finding{
		{Path: "identity.key", Code: "risk-filename"},
		{Path: "mail.txt", Code: "email-address"},
		{Path: "material.txt", Code: "pem-material"},
		{Path: "null.json", Code: "invalid-or-null-json"},
		{Path: "nul.txt", Code: "nul-byte"},
		{Path: "binary.dat", Code: "binary-or-invalid-utf8"},
	}
	for _, check := range checks {
		if !hasFinding(findings, check.Path, check.Code) {
			t.Fatalf("missing finding %+v in %v", check, findings)
		}
	}
}

func TestScannerDoesNotFlagCurrentRepository(t *testing.T) {
	findings, err := ScanProductionTree(repositoryRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("scanner flagged its own production source: %v", findings)
	}
}

func TestBrandScannerRequiresTokenBoundaries(t *testing.T) {
	if containsASCIIToken([]byte("historicalartifactsusedatruntime"), []byte("su"+"se")) {
		t.Fatal("identifier substring was treated as a brand token")
	}
	if !containsASCIIToken([]byte("module github.com/ran"+"cher/example"), []byte("ran"+"cher")) {
		t.Fatal("repository path brand token was not detected")
	}
}

func TestScannerIgnoresRootGitAdministrativeEntry(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, ".git", "gitdir: C:/Us"+"ers/private/legacy")
	findings, err := ScanProductionTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("root .git administrative entry was scanned: %v", findings)
	}
}
