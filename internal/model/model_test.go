package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func testRef(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func testDocument(operation, state string, observed, target, renewal uint64, renewable bool) string {
	return fmt.Sprintf(`{
"apiVersion":%q,
"operation":%q,
"requestRef":%q,
"subjectRef":%q,
"roleRef":%q,
"policySetRef":%q,
"audienceRef":%q,
"idempotencyRef":%q,
"lease":{
  "leaseRef":%q,
  "currentState":%q,
  "observedGeneration":%d,
  "expectedGeneration":%d,
  "targetGeneration":%d,
  "renewalCount":%d,
  "policyCount":2,
  "ttlSeconds":300,
  "wrapTTLSeconds":60,
  "renewable":%t,
  "notBefore":"2026-01-01T00:00:00Z",
  "expiresAt":"2026-01-01T00:05:00Z"
},
"assertions":{
  "subjectAuthenticated":true,
  "policyAuthorized":true,
  "issuerAttested":true,
  "transportProtected":true,
  "requestFresh":true
}}`, APIVersion, operation, testRef("1"), testRef("2"), testRef("3"), testRef("4"),
		testRef("5"), testRef("6"), testRef("7"), state, observed, observed, target, renewal, renewable)
}

func parseTestDocument(t *testing.T, document string) Request {
	t.Helper()
	request, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return request
}

func TestLifecycleTransitions(t *testing.T) {
	tests := []struct {
		operation, state, targetState string
		observed, target, renewal     uint64
		renewable                     bool
		targetRenewal                 uint64
	}{
		{operation: "issue", state: "absent", targetState: "active", target: 1, renewable: true},
		{operation: "renew", state: "active", targetState: "active", observed: 4, target: 4, renewal: 8, renewable: true, targetRenewal: 9},
		{operation: "rotate", state: "active", targetState: "active", observed: 4, target: 5, renewal: 8, renewable: true},
		{operation: "revoke", state: "active", targetState: "revoked", observed: 4, target: 4, renewal: 8, renewable: false, targetRenewal: 8},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			request := parseTestDocument(t, testDocument(test.operation, test.state, test.observed, test.target, test.renewal, test.renewable))
			plan := BuildPlan(request)
			if plan.Transition.ToState != test.targetState || plan.Transition.TargetGeneration != test.target ||
				plan.Transition.TargetRenewalCount != test.targetRenewal {
				t.Fatalf("unexpected transition: %#v", plan.Transition)
			}
		})
	}
}

func TestRejectsInvalidTransitions(t *testing.T) {
	validRenew := testDocument("renew", "active", 2, 2, 1, true)
	invalid := []string{
		testDocument("issue", "active", 0, 1, 0, true),
		testDocument("issue", "absent", 0, 2, 0, true),
		testDocument("renew", "active", 2, 2, 1, false),
		testDocument("renew", "active", 2, 3, 1, true),
		testDocument("rotate", "active", 2, 2, 0, true),
		testDocument("rotate", "revoked", 2, 3, 0, true),
		testDocument("revoke", "absent", 0, 0, 0, false),
		strings.Replace(validRenew, `"expectedGeneration":2`, `"expectedGeneration":1`, 1),
		strings.Replace(validRenew, `"renewalCount":1`, `"renewalCount":1000`, 1),
	}
	for index, document := range invalid {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("invalid transition %d was accepted", index)
		}
	}
}

func TestRejectsSchemaSmugglingAndMaterial(t *testing.T) {
	base := testDocument("issue", "absent", 0, 1, 0, true)
	invalid := []string{
		strings.Replace(base, `"operation":"issue"`, `"operation":"issue","operation":"issue"`, 1),
		strings.Replace(base, `"operation":"issue"`, `"Operation":"issue"`, 1),
		strings.Replace(base, `"operation":"issue"`, `"operation":null`, 1),
		strings.Replace(base, `"requestRef":`, `"token":"secret-material","requestRef":`, 1),
		strings.Replace(base, `"requestRef":`, `"accessor":"raw-accessor","requestRef":`, 1),
		strings.Replace(base, `"requestRef":`, `"policies":["admin"],"requestRef":`, 1),
		strings.Replace(base, `"requestRef":`, `"vaultURL":"https://example.invalid","requestRef":`, 1),
		strings.Replace(base, `"requestRef":`, `"hostKeyPath":"/private/key","requestRef":`, 1),
		base + `{}`,
	}
	for index, document := range invalid {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("schema-smuggling input %d was accepted", index)
		}
	}
}

func TestRejectsInvalidReferencesAndReferenceReuse(t *testing.T) {
	base := testDocument("issue", "absent", 0, 1, 0, true)
	invalid := []string{
		strings.Replace(base, testRef("1"), "sha256:"+strings.Repeat("A", 64), 1),
		strings.Replace(base, testRef("1"), "/tmp/request", 1),
		strings.Replace(base, testRef("2"), testRef("1"), 1),
		strings.Replace(base, testRef("7"), testRef("6"), 1),
	}
	for index, document := range invalid {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("invalid reference input %d was accepted", index)
		}
	}
}

func TestLeaseBoundsAndCanonicalTime(t *testing.T) {
	base := testDocument("issue", "absent", 0, 1, 0, true)
	invalid := []string{
		strings.Replace(base, `"policyCount":2`, `"policyCount":0`, 1),
		strings.Replace(base, `"policyCount":2`, `"policyCount":65`, 1),
		strings.Replace(base, `"ttlSeconds":300`, `"ttlSeconds":59`, 1),
		strings.Replace(base, `"ttlSeconds":300`, `"ttlSeconds":43201`, 1),
		strings.Replace(base, `"wrapTTLSeconds":60`, `"wrapTTLSeconds":29`, 1),
		strings.Replace(base, `"wrapTTLSeconds":60`, `"wrapTTLSeconds":301`, 1),
		strings.Replace(base, `2026-01-01T00:05:00Z`, `2026-01-01T00:04:59Z`, 1),
		strings.Replace(base, `2026-01-01T00:00:00Z`, `2026-01-01T00:00:00+00:00`, 1),
		strings.Replace(base, `"renewable":true`, `"renewable":null`, 1),
	}
	for index, document := range invalid {
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("invalid bound input %d was accepted", index)
		}
	}
}

func TestAssertionsAreRequiredAndRemainUnverified(t *testing.T) {
	base := testDocument("issue", "absent", 0, 1, 0, true)
	for _, key := range []string{"subjectAuthenticated", "policyAuthorized", "issuerAttested", "transportProtected", "requestFresh"} {
		document := strings.Replace(base, `"`+key+`":true`, `"`+key+`":false`, 1)
		if _, err := Parse(strings.NewReader(document)); err == nil {
			t.Fatalf("false assertion %s was accepted", key)
		}
	}
	status := UnverifiedAssertions()
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(encoded), assertedUnverified) != 5 || strings.Contains(string(encoded), `"verified"`) {
		t.Fatalf("unexpected assertion status: %s", encoded)
	}
}

func TestPlanIsDeterministicBlockedAndDoesNotExposeReferences(t *testing.T) {
	request := parseTestDocument(t, testDocument("rotate", "active", 9, 10, 12, true))
	first := BuildPlan(request)
	second := BuildPlan(request)
	if !reflect.DeepEqual(first, second) || !strings.HasPrefix(first.PlanID, "sha256:") || len(first.PlanID) != 71 {
		t.Fatal("plan was not deterministic")
	}
	for _, step := range first.Steps {
		if step.Status != "blocked" || step.Effect != "none" {
			t.Fatalf("executable step found: %#v", step)
		}
	}
	for _, gate := range first.Gates {
		if gate.Status != "blocked" || gate.Satisfied {
			t.Fatalf("satisfied gate found: %#v", gate)
		}
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{request.RequestRef, request.SubjectRef, request.RoleRef, request.PolicySetRef, request.AudienceRef, request.IdempotencyRef, request.Lease.LeaseRef} {
		if strings.Contains(string(encoded), reference) {
			t.Fatal("plan exposed an opaque reference")
		}
	}
}

func TestEveryControlIsFalse(t *testing.T) {
	value := reflect.ValueOf(DisabledControls())
	if value.NumField() != 17 {
		t.Fatalf("unexpected control count: %d", value.NumField())
	}
	for index := 0; index < value.NumField(); index++ {
		if value.Field(index).Bool() {
			t.Fatalf("control %s is enabled", value.Type().Field(index).Name)
		}
	}
}
