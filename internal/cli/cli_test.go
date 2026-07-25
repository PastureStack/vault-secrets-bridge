package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/PastureStack/vault-secrets-bridge/internal/model"
)

type panicReader struct{}

func (panicReader) Read([]byte) (int, error) { panic("stdin was read") }

func cliRef(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func cliDocument() string {
	return fmt.Sprintf(`{
"apiVersion":%q,"operation":"issue","requestRef":%q,"subjectRef":%q,"roleRef":%q,"policySetRef":%q,"audienceRef":%q,"idempotencyRef":%q,
"lease":{"leaseRef":%q,"currentState":"absent","observedGeneration":0,"expectedGeneration":0,"targetGeneration":1,"renewalCount":0,"policyCount":2,"ttlSeconds":300,"wrapTTLSeconds":60,"renewable":true,"notBefore":"2026-01-01T00:00:00Z","expiresAt":"2026-01-01T00:05:00Z"},
"assertions":{"subjectAuthenticated":true,"policyAuthorized":true,"issuerAttested":true,"transportProtected":true,"requestFresh":true}}`,
		model.APIVersion, cliRef("1"), cliRef("2"), cliRef("3"), cliRef("4"), cliRef("5"), cliRef("6"), cliRef("7"))
}

func runCLI(args []string, input string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCapabilitiesNeverReadsStdin(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"capabilities"}, panicReader{}, &stdout, &stderr); code != 0 {
		t.Fatalf("unexpected exit %d: %s", code, stderr.String())
	}
	if !allControlsFalse(t, stdout.Bytes()) {
		t.Fatal("a capability control was enabled")
	}
	if !strings.Contains(stdout.String(), `"operations":["issue","renew","revoke","rotate"]`) {
		t.Fatal("capabilities did not expose the frozen operation set")
	}
}

func TestValidateAndPlanDoNotEchoOpaqueReferences(t *testing.T) {
	input := cliDocument()
	for _, command := range []string{"validate", "plan"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runCLI([]string{command}, input)
			if code != 0 {
				t.Fatalf("unexpected exit %d: %s", code, stderr)
			}
			for _, character := range []string{"1", "2", "3", "4", "5", "6", "7"} {
				if strings.Contains(stdout, strings.Repeat(character, 64)) {
					t.Fatal("output echoed an opaque reference")
				}
			}
			if strings.Contains(stdout, `"verified"`) {
				t.Fatal("output represented assertions as verified")
			}
			if !allControlsFalse(t, []byte(stdout)) {
				t.Fatal("a control was enabled")
			}
		})
	}
}

func TestInvalidInputUsesGenericNonEchoingError(t *testing.T) {
	input := strings.Replace(cliDocument(), `"requestRef":`, `"token":"TOP-SECRET-MARKER","requestRef":`, 1)
	code, stdout, stderr := runCLI([]string{"plan"}, input)
	if code == 0 || stdout != "" {
		t.Fatal("invalid input unexpectedly succeeded")
	}
	if strings.Contains(stderr, "TOP-SECRET-MARKER") || strings.Contains(stderr, "token") {
		t.Fatal("error echoed rejected input")
	}
	if !strings.Contains(stderr, `"code":"invalid-input"`) {
		t.Fatal("missing generic error code")
	}
}

func TestCommandsAreStdinOnlyAndUsageErrorsDoNotRead(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"plan", "unexpected-argument"}, panicReader{}, &stdout, &stderr); code == 0 {
		t.Fatal("positional input was accepted")
	}
	if !strings.Contains(stderr.String(), `"code":"invalid-usage"`) {
		t.Fatal("missing generic usage error")
	}
}

func TestLocaleParity(t *testing.T) {
	input := cliDocument()
	enCode, enOut, enErr := runCLI([]string{"--locale", LocaleEnglish, "plan"}, input)
	zhCode, zhOut, zhErr := runCLI([]string{"--locale", LocaleChinese, "plan"}, input)
	if enCode != 0 || zhCode != 0 {
		t.Fatalf("locale run failed: en=%s zh=%s", enErr, zhErr)
	}
	var english map[string]any
	var chinese map[string]any
	if err := json.Unmarshal([]byte(enOut), &english); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(zhOut), &chinese); err != nil {
		t.Fatal(err)
	}
	stripLocalizedFields(english)
	stripLocalizedFields(chinese)
	if !reflect.DeepEqual(english, chinese) {
		t.Fatal("locales changed semantic output")
	}
	if !strings.Contains(zhOut, "本離線契約禁止處理權杖或機密內容") ||
		!strings.Contains(enOut, "This offline contract prohibits token or secret material") {
		t.Fatal("localized diagnostics are missing")
	}
}

func TestPlanOutputIsDeterministic(t *testing.T) {
	input := cliDocument()
	firstCode, first, firstErr := runCLI([]string{"plan"}, input)
	secondCode, second, secondErr := runCLI([]string{"plan"}, input)
	if firstCode != 0 || secondCode != 0 {
		t.Fatalf("plan failed: %s %s", firstErr, secondErr)
	}
	if first != second {
		t.Fatal("identical requests produced different output")
	}
}

func TestUnsupportedLocaleIsGeneric(t *testing.T) {
	code, stdout, stderr := runCLI([]string{"--locale", "invalid", "capabilities"}, "ignored")
	if code == 0 || stdout != "" || !strings.Contains(stderr, `"code":"invalid-usage"`) {
		t.Fatal("unsupported locale was not rejected generically")
	}
}

func allControlsFalse(t *testing.T, output []byte) bool {
	t.Helper()
	var decoded struct {
		Controls map[string]bool `json:"controls"`
	}
	if err := json.Unmarshal(output, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Controls) != 17 {
		t.Fatalf("unexpected control count: %d", len(decoded.Controls))
	}
	for _, enabled := range decoded.Controls {
		if enabled {
			return false
		}
	}
	return true
}

func stripLocalizedFields(output map[string]any) {
	delete(output, "locale")
	if diagnostics, ok := output["diagnostics"].([]any); ok {
		for _, item := range diagnostics {
			if diagnostic, ok := item.(map[string]any); ok {
				delete(diagnostic, "message")
			}
		}
	}
}
