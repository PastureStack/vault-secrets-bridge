// Package safety provides a recursive, deterministic public-tree gate. The
// gate skips only the root .git directory. Test files remain subject to every
// content check and are excluded only from the production import policy.
package safety

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/PastureStack/vault-secrets-bridge/internal/strictjson"
)

var RequiredReadmeOpening = "PastureStack is an independent community effort to preserve, audit, and modernize the Ran" +
	"cher 1.6 ecosystem. It is not affiliated with or endorsed by Ran" + "cher Labs or SU" + "SE."

type Finding struct {
	Path string
	Code string
}

var allowedImports = map[string]struct{}{
	"bytes": {}, "crypto/sha256": {}, "encoding/binary": {}, "encoding/hex": {},
	"encoding/json": {}, "errors": {}, "flag": {}, "go/ast": {}, "go/parser": {},
	"go/token": {}, "hash": {}, "io": {}, "io/fs": {}, "os": {}, "path/filepath": {},
	"sort": {}, "strconv": {}, "strings": {}, "time": {}, "unicode/utf8": {},
}

var runtimeAllowedImports = map[string]struct{}{
	"bytes": {}, "context": {}, "crypto": {}, "crypto/aes": {}, "crypto/cipher": {},
	"crypto/hmac": {}, "crypto/rand": {}, "crypto/rsa": {}, "crypto/sha256": {},
	"crypto/tls": {}, "crypto/x509": {}, "encoding/base64": {}, "encoding/hex": {},
	"encoding/json": {}, "encoding/pem": {}, "errors": {}, "flag": {}, "fmt": {},
	"io": {}, "log": {}, "mime": {}, "net": {}, "net/http": {}, "net/url": {},
	"os": {}, "os/signal": {}, "path": {}, "path/filepath": {}, "sort": {},
	"strconv": {}, "strings": {}, "sync": {}, "sync/atomic": {}, "syscall": {},
	"time": {},
}

var commandOSSelectors = map[string]map[string]struct{}{
	"cmd/vault-secrets-bridge/main.go": {
		"Args": {}, "Exit": {}, "Stderr": {}, "Stdin": {}, "Stdout": {},
	},
}

var runtimeOSSelectors = map[string]map[string]struct{}{
	"internal/broker/config.go": {"Getenv": {}, "Lstat": {}, "Open": {}},
	"internal/broker/server.go": {"Interrupt": {}},
	"internal/broker/state.go": {
		"Chmod": {}, "CreateTemp": {}, "ErrNotExist": {}, "Lstat": {},
		"MkdirAll": {}, "ReadFile": {}, "Remove": {}, "Rename": {},
	},
}

var safetyToolOSSelectors = map[string]map[string]struct{}{
	"internal/safety/binary.go":  {"ReadFile": {}},
	"internal/safety/legal.go":   {"ReadFile": {}},
	"internal/safety/scanner.go": {"ModeSymlink": {}, "ReadFile": {}},
}

var productionTimeSelectors = map[string]map[string]struct{}{
	"internal/model/model.go": {
		"Duration": {}, "Parse": {}, "RFC3339": {}, "Second": {},
	},
	"internal/broker/config.go": {
		"Duration": {}, "Hour": {}, "Minute": {}, "ParseDuration": {}, "Second": {},
	},
	"internal/broker/nonce.go": {
		"Duration": {}, "Time": {},
	},
	"internal/broker/platform.go": {
		"Duration": {}, "Second": {},
	},
	"internal/broker/server.go": {
		"Duration": {}, "NewTicker": {}, "Now": {}, "Second": {}, "Time": {},
	},
	"internal/broker/types.go": {
		"Duration": {}, "Parse": {}, "RFC3339Nano": {}, "Time": {},
	},
}

var legacyImplementationTokens = [][]byte{
	[]byte("github.com/ran" + "cher/"), []byte("/var/lib/ran" + "cher"),
	[]byte("cattle" + "_agent_"), []byte("cattle" + "_url"),
	[]byte("vault-token-" + "server"),
	[]byte("/v1-vault-" + "driver"), []byte("x-vault-driver-" + "signature"),
	[]byte("169.254." + "169.250"), []byte("update-ran" + "cher-ssl"),
	[]byte("/var/run/docker" + ".sock"),
}

const internalSafetyImport = "github.com/PastureStack/vault-secrets-bridge/internal/safety"

// ScanProductionTree checks every public file recursively. Go test files are
// included in content and filename checks, but excluded from the production
// import and effect policy. It does not follow symlinks and reports them as
// release-blocking findings.
func ScanProductionTree(root string) ([]Finding, error) {
	findings := make([]Finding, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if relative == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{Path: relative, Code: "symlink-entry"})
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			findings = append(findings, Finding{Path: relative, Code: "non-regular-entry"})
			return nil
		}
		findings = append(findings, scanFilename(relative)...)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		findings = append(findings, scanPublicContent(relative, content)...)
		if strings.HasSuffix(strings.ToLower(relative), ".go") && !strings.HasSuffix(relative, "_test.go") {
			findings = append(findings, scanGoFile(relative, path, content)...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Code < findings[right].Code
		}
		return findings[left].Path < findings[right].Path
	})
	return uniqueFindings(findings), nil
}

func scanPublicContent(relative string, content []byte) []Finding {
	findings := make([]Finding, 0)
	legalPath := legalOrProvenancePath(relative)
	if bytes.IndexByte(content, 0) >= 0 {
		findings = append(findings, Finding{Path: relative, Code: "nul-byte"})
	}
	if !utf8.Valid(content) {
		findings = append(findings, Finding{Path: relative, Code: "binary-or-invalid-utf8"})
		return findings
	}
	lower := bytes.ToLower(content)
	privateTokens := [][]byte{
		[]byte("chen" + "21019"), []byte("gmail" + ".com"),
		[]byte("c:" + `\` + "users" + `\`), []byte("/" + "home" + "/"),
		[]byte("/" + "users" + "/"), []byte("user" + "profile"),
	}
	for _, forbidden := range privateTokens {
		if bytes.Contains(lower, forbidden) {
			findings = append(findings, Finding{Path: relative, Code: "private-namespace"})
			break
		}
	}
	// Exact legal and attribution artifacts may contain third-party contact
	// addresses that cannot be edited without corrupting the preserved text.
	// Private namespace tokens remain prohibited on every path.
	if !legalPath && containsEmail(content) {
		findings = append(findings, Finding{Path: relative, Code: "email-address"})
	}
	if containsPEM(content) {
		findings = append(findings, Finding{Path: relative, Code: "pem-material"})
	}
	if strings.HasSuffix(strings.ToLower(relative), ".json") {
		if _, err := strictjson.Parse(bytes.NewReader(content)); err != nil {
			findings = append(findings, Finding{Path: relative, Code: "invalid-or-null-json"})
		}
	}

	if relative == "README.md" && !bytes.HasPrefix(content, []byte(RequiredReadmeOpening+"\n\n")) {
		findings = append(findings, Finding{Path: relative, Code: "readme-opening"})
	}
	brandContent := lower
	if relative == "README.md" && bytes.HasPrefix(content, []byte(RequiredReadmeOpening+"\n\n")) {
		remainder := content[len(RequiredReadmeOpening)+2:]
		if paragraphEnd := bytes.Index(remainder, []byte("\n\n")); paragraphEnd >= 0 &&
			bytes.HasPrefix(remainder, []byte("**Upstream:**")) {
			remainder = remainder[paragraphEnd+2:]
		}
		brandContent = bytes.ToLower(remainder)
	}
	if legalPath {
		return findings
	}
	if containsASCIIToken(brandContent, []byte("ran"+"cher")) || containsASCIIToken(brandContent, []byte("su"+"se")) {
		findings = append(findings, Finding{Path: relative, Code: "legacy-brand"})
	}
	for _, forbidden := range legacyImplementationTokens {
		if bytes.Contains(brandContent, forbidden) {
			findings = append(findings, Finding{Path: relative, Code: "legacy-implementation"})
			break
		}
	}
	if containsLegacyBinaryName(brandContent) {
		findings = append(findings, Finding{Path: relative, Code: "legacy-implementation"})
	}
	return findings
}

func containsASCIIToken(content, token []byte) bool {
	remaining := content
	consumed := 0
	for {
		index := bytes.Index(remaining, token)
		if index < 0 {
			return false
		}
		absolute := consumed + index
		leftBoundary := absolute == 0 || !asciiAlphaNumeric(content[absolute-1])
		right := absolute + len(token)
		rightBoundary := right == len(content) || !asciiAlphaNumeric(content[right])
		if leftBoundary && rightBoundary {
			return true
		}
		step := index + 1
		remaining = remaining[step:]
		consumed += step
	}
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func containsLegacyBinaryName(content []byte) bool {
	return bytes.Contains(content, []byte("secrets-"+"bridge-v2"))
}

func scanFilename(relative string) []Finding {
	lower := strings.ToLower(filepath.ToSlash(relative))
	base := filepath.Base(lower)
	riskyNames := map[string]struct{}{
		".env": {}, "credentials": {}, "credentials.json": {}, "id_dsa": {},
		"id_ecdsa": {}, "id_ed25519": {}, "id_rsa": {}, "known_hosts": {},
		"password": {}, "passwords": {}, "token": {}, "tokens": {},
	}
	if _, risky := riskyNames[base]; risky {
		return []Finding{{Path: relative, Code: "risk-filename"}}
	}
	for _, suffix := range []string{
		".a", ".bin", ".cer", ".crt", ".der", ".dll", ".dylib", ".exe", ".jks",
		".key", ".kdb", ".o", ".p12", ".pem", ".pfx", ".so", ".tar", ".zip",
	} {
		if strings.HasSuffix(base, suffix) {
			return []Finding{{Path: relative, Code: "risk-filename"}}
		}
	}
	return nil
}

func containsPEM(content []byte) bool {
	prefix := []byte("-----BE" + "GIN ")
	if !bytes.Contains(content, prefix) {
		return false
	}
	return bytes.Contains(content, []byte("PRIVATE "+"KEY-----")) ||
		bytes.Contains(content, []byte("CERTIFICATE-----")) ||
		bytes.Contains(content, []byte("OPENSSH "+"PRIVATE KEY-----"))
}

func containsEmail(content []byte) bool {
	for index, character := range content {
		if character != '@' || index == 0 || index+1 >= len(content) || !emailLocalByte(content[index-1]) || !emailDomainByte(content[index+1]) {
			continue
		}
		left := index - 1
		for left > 0 && emailLocalByte(content[left-1]) {
			left--
		}
		right := index + 1
		for right < len(content) && emailDomainByte(content[right]) {
			right++
		}
		domain := content[index+1 : right]
		lastDot := bytes.LastIndexByte(domain, '.')
		if left < index && lastDot > 0 && len(domain)-lastDot-1 >= 2 &&
			domain[0] != '.' && domain[len(domain)-1] != '.' {
			return true
		}
	}
	return false
}

func emailLocalByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || strings.ContainsRune("._%+-", rune(value))
}

func emailDomainByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '.' || value == '-'
}

func uniqueFindings(findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	result := findings[:1]
	for _, finding := range findings[1:] {
		last := result[len(result)-1]
		if finding.Path != last.Path || finding.Code != last.Code {
			result = append(result, finding)
		}
	}
	return result
}

func legalOrProvenancePath(relative string) bool {
	return relative == "LICENSE" || relative == "ORIGIN.md" || strings.HasPrefix(relative, "LICENSES/")
}

func scanGoFile(relative, path string, content []byte) []Finding {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, path, content, 0)
	if err != nil {
		return []Finding{{Path: relative, Code: "invalid-go-syntax"}}
	}
	findings := make([]Finding, 0)
	normalized := filepath.ToSlash(relative)
	runtimeFile := strings.HasPrefix(normalized, "internal/broker/")
	aliases := make(map[string]string)
	allowedOSSelectors, osAllowedInFile := allowedOSSelectorsForFile(relative)
	allowedTimeSelectors, timeAllowedInFile := productionTimeSelectors[filepath.ToSlash(relative)]
	for _, imported := range parsed.Imports {
		importPath, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			findings = append(findings, Finding{Path: relative, Code: "invalid-import"})
			continue
		}
		_, allowed := allowedImports[importPath]
		if runtimeFile {
			_, allowed = runtimeAllowedImports[importPath]
		}
		if !allowed && !strings.HasPrefix(importPath, "github.com/PastureStack/vault-secrets-bridge/") {
			findings = append(findings, Finding{Path: relative, Code: "import-not-allowed"})
		}
		if importPath == "os" && !osAllowedInFile {
			findings = append(findings, Finding{Path: relative, Code: "os-import-not-allowed"})
		}
		if importPath == "time" && !timeAllowedInFile {
			findings = append(findings, Finding{Path: relative, Code: "time-import-not-allowed"})
		}
		if importPath == internalSafetyImport {
			findings = append(findings, Finding{Path: relative, Code: "safety-package-import-not-allowed"})
		}
		alias := importPath
		if slash := strings.LastIndexByte(alias, '/'); slash >= 0 {
			alias = alias[slash+1:]
		}
		if imported.Name != nil {
			alias = imported.Name.Name
			if alias == "." || alias == "_" {
				findings = append(findings, Finding{Path: relative, Code: "import-alias-not-allowed"})
				continue
			}
		}
		aliases[alias] = importPath
	}

	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if chain, ok := selectorChainForImport(selector, aliases, "os"); ok {
			if len(chain) != 1 {
				findings = append(findings, Finding{Path: relative, Code: "os-selector-chain-not-allowed"})
				return true
			}
			if _, allowed := allowedOSSelectors[chain[0]]; !osAllowedInFile || !allowed {
				findings = append(findings, Finding{Path: relative, Code: "os-selector-not-allowed"})
			}
		}
		if chain, ok := selectorChainForImport(selector, aliases, "time"); ok {
			if len(chain) != 1 {
				findings = append(findings, Finding{Path: relative, Code: "time-selector-chain-not-allowed"})
				return true
			}
			if _, allowed := allowedTimeSelectors[chain[0]]; !timeAllowedInFile || !allowed {
				findings = append(findings, Finding{Path: relative, Code: "time-selector-not-allowed"})
			}
		}
		return true
	})
	return findings
}

func allowedOSSelectorsForFile(relative string) (map[string]struct{}, bool) {
	normalized := filepath.ToSlash(relative)
	if selectors, allowed := commandOSSelectors[normalized]; allowed {
		return selectors, true
	}
	if selectors, allowed := runtimeOSSelectors[normalized]; allowed {
		return selectors, true
	}
	selectors, allowed := safetyToolOSSelectors[normalized]
	return selectors, allowed
}

func selectorChainForImport(selector *ast.SelectorExpr, aliases map[string]string, importPath string) ([]string, bool) {
	switch expression := selector.X.(type) {
	case *ast.Ident:
		if aliases[expression.Name] != importPath {
			return nil, false
		}
		return []string{selector.Sel.Name}, true
	case *ast.SelectorExpr:
		chain, ok := selectorChainForImport(expression, aliases, importPath)
		if !ok {
			return nil, false
		}
		return append(chain, selector.Sel.Name), true
	default:
		return nil, false
	}
}
