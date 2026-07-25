// Package model defines the side-effect-free Vault lease planning contract.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PastureStack/vault-secrets-bridge/internal/strictjson"
)

const (
	APIVersion         = "pasturestack.io/vault-secrets-bridge/v1alpha1"
	ContractVersion    = uint64(1)
	MinTTLSeconds      = uint64(60)
	MaxTTLSeconds      = uint64(12 * 60 * 60)
	MinWrapTTL         = uint64(30)
	MaxWrapTTL         = uint64(10 * 60)
	MaxPolicyCount     = uint64(64)
	MaxRenewalCount    = uint64(1000)
	assertedUnverified = "asserted-unverified"
)

var ErrInvalid = errors.New("invalid lease planning request")

type Request struct {
	Operation      string
	RequestRef     string
	SubjectRef     string
	RoleRef        string
	PolicySetRef   string
	AudienceRef    string
	IdempotencyRef string
	Lease          Lease
	Assertions     Assertions
}

type Lease struct {
	LeaseRef           string `json:"leaseRef"`
	CurrentState       string `json:"currentState"`
	ObservedGeneration uint64 `json:"observedGeneration"`
	ExpectedGeneration uint64 `json:"expectedGeneration"`
	TargetGeneration   uint64 `json:"targetGeneration"`
	RenewalCount       uint64 `json:"renewalCount"`
	PolicyCount        uint64 `json:"policyCount"`
	TTLSeconds         uint64 `json:"ttlSeconds"`
	WrapTTLSeconds     uint64 `json:"wrapTTLSeconds"`
	Renewable          bool   `json:"renewable"`
	NotBefore          string `json:"notBefore"`
	ExpiresAt          string `json:"expiresAt"`
}

type Assertions struct {
	SubjectAuthenticated bool `json:"subjectAuthenticated"`
	PolicyAuthorized     bool `json:"policyAuthorized"`
	IssuerAttested       bool `json:"issuerAttested"`
	TransportProtected   bool `json:"transportProtected"`
	RequestFresh         bool `json:"requestFresh"`
}

type Controls struct {
	Network         bool `json:"network"`
	VaultAPI        bool `json:"vaultAPI"`
	MetadataAPI     bool `json:"metadataAPI"`
	ControlPlaneAPI bool `json:"controlPlaneAPI"`
	TokenRead       bool `json:"tokenRead"`
	TokenWrite      bool `json:"tokenWrite"`
	KeyRead         bool `json:"keyRead"`
	Sign            bool `json:"sign"`
	VerifySignature bool `json:"verifySignature"`
	Encrypt         bool `json:"encrypt"`
	Decrypt         bool `json:"decrypt"`
	FilesystemWrite bool `json:"filesystemWrite"`
	Tmpfs           bool `json:"tmpfs"`
	BindMount       bool `json:"bindMount"`
	StateWrite      bool `json:"stateWrite"`
	ClockRead       bool `json:"clockRead"`
	Execution       bool `json:"execution"`
}

type AssertionStatus struct {
	SubjectAuthentication string `json:"subjectAuthentication"`
	PolicyAuthorization   string `json:"policyAuthorization"`
	IssuerAttestation     string `json:"issuerAttestation"`
	TransportProtection   string `json:"transportProtection"`
	RequestFreshness      string `json:"requestFreshness"`
}

type Summary struct {
	PolicyCount    uint64 `json:"policyCount"`
	TTLSeconds     uint64 `json:"ttlSeconds"`
	WrapTTLSeconds uint64 `json:"wrapTTLSeconds"`
	Renewable      bool   `json:"renewable"`
	RenewalCount   uint64 `json:"renewalCount"`
}

type Transition struct {
	FromState          string `json:"fromState"`
	ToState            string `json:"toState"`
	ObservedGeneration uint64 `json:"observedGeneration"`
	ExpectedGeneration uint64 `json:"expectedGeneration"`
	TargetGeneration   uint64 `json:"targetGeneration"`
	TargetRenewalCount uint64 `json:"targetRenewalCount"`
}

type Step struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Effect string `json:"effect"`
}

type Gate struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Satisfied bool   `json:"satisfied"`
}

type Plan struct {
	PlanID      string
	Operation   string
	Transition  Transition
	Summary     Summary
	Assertions  AssertionStatus
	Steps       []Step
	Gates       []Gate
	Diagnostics []string
	Controls    Controls
}

// Parse accepts exactly one null-free, exact-case JSON document.
func Parse(reader io.Reader) (Request, error) {
	value, err := strictjson.Parse(reader)
	if err != nil || value.Kind != strictjson.KindObject {
		return Request{}, ErrInvalid
	}
	root := value.Object
	if !exactKeys(root,
		"apiVersion", "operation", "requestRef", "subjectRef", "roleRef",
		"policySetRef", "audienceRef", "idempotencyRef", "lease", "assertions") {
		return Request{}, ErrInvalid
	}

	request := Request{}
	if apiVersion, ok := stringValue(root["apiVersion"]); !ok || apiVersion != APIVersion {
		return Request{}, ErrInvalid
	}
	if request.Operation, err = allowedString(root["operation"], "issue", "renew", "rotate", "revoke"); err != nil {
		return Request{}, ErrInvalid
	}

	refTargets := []*string{
		&request.RequestRef, &request.SubjectRef, &request.RoleRef, &request.PolicySetRef,
		&request.AudienceRef, &request.IdempotencyRef,
	}
	refKeys := []string{"requestRef", "subjectRef", "roleRef", "policySetRef", "audienceRef", "idempotencyRef"}
	for index, target := range refTargets {
		if *target, err = referenceValue(root[refKeys[index]]); err != nil {
			return Request{}, ErrInvalid
		}
	}

	if request.Lease, err = parseLease(root["lease"]); err != nil {
		return Request{}, ErrInvalid
	}
	if request.Assertions, err = parseAssertions(root["assertions"]); err != nil {
		return Request{}, ErrInvalid
	}

	allRefs := []string{
		request.RequestRef, request.SubjectRef, request.RoleRef, request.PolicySetRef,
		request.AudienceRef, request.IdempotencyRef, request.Lease.LeaseRef,
	}
	if !allUnique(allRefs) || !validTransition(request.Operation, request.Lease) {
		return Request{}, ErrInvalid
	}
	return request, nil
}

func parseLease(value strictjson.Value) (Lease, error) {
	object, ok := objectValue(value)
	if !ok || !exactKeys(object,
		"leaseRef", "currentState", "observedGeneration", "expectedGeneration",
		"targetGeneration", "renewalCount", "policyCount", "ttlSeconds",
		"wrapTTLSeconds", "renewable", "notBefore", "expiresAt") {
		return Lease{}, ErrInvalid
	}

	lease := Lease{}
	var err error
	if lease.LeaseRef, err = referenceValue(object["leaseRef"]); err != nil {
		return Lease{}, ErrInvalid
	}
	if lease.CurrentState, err = allowedString(object["currentState"], "absent", "active", "revoked"); err != nil {
		return Lease{}, ErrInvalid
	}
	numericTargets := []*uint64{
		&lease.ObservedGeneration, &lease.ExpectedGeneration, &lease.TargetGeneration,
		&lease.RenewalCount, &lease.PolicyCount, &lease.TTLSeconds, &lease.WrapTTLSeconds,
	}
	numericKeys := []string{
		"observedGeneration", "expectedGeneration", "targetGeneration", "renewalCount",
		"policyCount", "ttlSeconds", "wrapTTLSeconds",
	}
	for index, target := range numericTargets {
		if *target, err = unsignedValue(object[numericKeys[index]]); err != nil {
			return Lease{}, ErrInvalid
		}
	}
	if lease.PolicyCount == 0 || lease.PolicyCount > MaxPolicyCount ||
		lease.TTLSeconds < MinTTLSeconds || lease.TTLSeconds > MaxTTLSeconds ||
		lease.WrapTTLSeconds < MinWrapTTL || lease.WrapTTLSeconds > MaxWrapTTL ||
		lease.WrapTTLSeconds > lease.TTLSeconds || lease.RenewalCount > MaxRenewalCount {
		return Lease{}, ErrInvalid
	}
	if lease.Renewable, ok = boolValue(object["renewable"]); !ok {
		return Lease{}, ErrInvalid
	}
	if lease.NotBefore, err = canonicalTimeValue(object["notBefore"]); err != nil {
		return Lease{}, ErrInvalid
	}
	if lease.ExpiresAt, err = canonicalTimeValue(object["expiresAt"]); err != nil {
		return Lease{}, ErrInvalid
	}
	notBefore, _ := time.Parse(time.RFC3339, lease.NotBefore)
	expiresAt, _ := time.Parse(time.RFC3339, lease.ExpiresAt)
	if !notBefore.Before(expiresAt) || expiresAt.Sub(notBefore) != time.Duration(lease.TTLSeconds)*time.Second {
		return Lease{}, ErrInvalid
	}
	return lease, nil
}

func parseAssertions(value strictjson.Value) (Assertions, error) {
	object, ok := objectValue(value)
	if !ok || !exactKeys(object,
		"subjectAuthenticated", "policyAuthorized", "issuerAttested",
		"transportProtected", "requestFresh") {
		return Assertions{}, ErrInvalid
	}
	assertions := Assertions{}
	targets := []*bool{
		&assertions.SubjectAuthenticated, &assertions.PolicyAuthorized, &assertions.IssuerAttested,
		&assertions.TransportProtected, &assertions.RequestFresh,
	}
	keys := []string{"subjectAuthenticated", "policyAuthorized", "issuerAttested", "transportProtected", "requestFresh"}
	for index, target := range targets {
		value, valid := boolValue(object[keys[index]])
		if !valid || !value {
			return Assertions{}, ErrInvalid
		}
		*target = value
	}
	return assertions, nil
}

func validTransition(operation string, lease Lease) bool {
	if lease.ExpectedGeneration != lease.ObservedGeneration {
		return false
	}
	switch operation {
	case "issue":
		return lease.CurrentState == "absent" && lease.ObservedGeneration == 0 &&
			lease.TargetGeneration == 1 && lease.RenewalCount == 0
	case "renew":
		return lease.CurrentState == "active" && lease.ObservedGeneration > 0 && lease.Renewable &&
			lease.TargetGeneration == lease.ObservedGeneration && lease.RenewalCount < MaxRenewalCount
	case "rotate":
		return lease.CurrentState == "active" && lease.ObservedGeneration > 0 &&
			lease.ObservedGeneration < ^uint64(0) && lease.TargetGeneration == lease.ObservedGeneration+1
	case "revoke":
		return lease.CurrentState == "active" && lease.ObservedGeneration > 0 &&
			lease.TargetGeneration == lease.ObservedGeneration
	default:
		return false
	}
}

func BuildPlan(request Request) Plan {
	transition := Transition{
		FromState:          request.Lease.CurrentState,
		ToState:            targetState(request.Operation),
		ObservedGeneration: request.Lease.ObservedGeneration,
		ExpectedGeneration: request.Lease.ExpectedGeneration,
		TargetGeneration:   request.Lease.TargetGeneration,
		TargetRenewalCount: targetRenewalCount(request),
	}
	return Plan{
		PlanID:     planID(request),
		Operation:  request.Operation,
		Transition: transition,
		Summary:    RequestSummary(request),
		Assertions: UnverifiedAssertions(),
		Steps:      blockedSteps(request.Operation),
		Gates:      blockedGates(),
		Diagnostics: []string{
			"assertions-unverified", "effects-disabled", "lease-state-unverified", "token-material-prohibited",
		},
		Controls: DisabledControls(),
	}
}

func RequestSummary(request Request) Summary {
	return Summary{
		PolicyCount:    request.Lease.PolicyCount,
		TTLSeconds:     request.Lease.TTLSeconds,
		WrapTTLSeconds: request.Lease.WrapTTLSeconds,
		Renewable:      request.Lease.Renewable,
		RenewalCount:   request.Lease.RenewalCount,
	}
}

func UnverifiedAssertions() AssertionStatus {
	return AssertionStatus{
		SubjectAuthentication: assertedUnverified,
		PolicyAuthorization:   assertedUnverified,
		IssuerAttestation:     assertedUnverified,
		TransportProtection:   assertedUnverified,
		RequestFreshness:      assertedUnverified,
	}
}

func DisabledControls() Controls { return Controls{} }

func blockedSteps(operation string) []Step {
	ids := []string{
		"authenticate-subject", "authorize-policy-set", "persist-lease-state",
		"protect-transport", "verify-issuer-attestation", "verify-request-freshness",
	}
	switch operation {
	case "issue":
		ids = append(ids, "create-scoped-lease", "wrap-token-material")
	case "renew":
		ids = append(ids, "renew-lease")
	case "rotate":
		ids = append(ids, "create-replacement-lease", "revoke-previous-lease", "switch-lease-atomically", "wrap-token-material")
	case "revoke":
		ids = append(ids, "revoke-lease")
	}
	sort.Strings(ids)
	steps := make([]Step, 0, len(ids))
	for _, id := range ids {
		steps = append(steps, Step{ID: id, Status: "blocked", Effect: "none"})
	}
	return steps
}

func blockedGates() []Gate {
	ids := []string{
		"atomic-rotation", "audit-write", "durable-idempotency", "issuer-attestation",
		"lease-state-lookup", "policy-authorization", "request-freshness", "request-signature-verification",
		"revoke-confirmation", "subject-authentication", "token-material-boundary", "trusted-clock",
		"vault-connectivity",
	}
	sort.Strings(ids)
	gates := make([]Gate, 0, len(ids))
	for _, id := range ids {
		gates = append(gates, Gate{ID: id, Status: "blocked", Satisfied: false})
	}
	return gates
}

func targetState(operation string) string {
	if operation == "revoke" {
		return "revoked"
	}
	return "active"
}

func targetRenewalCount(request Request) uint64 {
	if request.Operation == "renew" {
		return request.Lease.RenewalCount + 1
	}
	if request.Operation == "issue" || request.Operation == "rotate" {
		return 0
	}
	return request.Lease.RenewalCount
}

func planID(request Request) string {
	normalized := struct {
		APIVersion     string     `json:"apiVersion"`
		Operation      string     `json:"operation"`
		RequestRef     string     `json:"requestRef"`
		SubjectRef     string     `json:"subjectRef"`
		RoleRef        string     `json:"roleRef"`
		PolicySetRef   string     `json:"policySetRef"`
		AudienceRef    string     `json:"audienceRef"`
		IdempotencyRef string     `json:"idempotencyRef"`
		Lease          Lease      `json:"lease"`
		Assertions     Assertions `json:"assertions"`
	}{
		APIVersion: APIVersion, Operation: request.Operation, RequestRef: request.RequestRef,
		SubjectRef: request.SubjectRef, RoleRef: request.RoleRef, PolicySetRef: request.PolicySetRef,
		AudienceRef: request.AudienceRef, IdempotencyRef: request.IdempotencyRef,
		Lease: request.Lease, Assertions: request.Assertions,
	}
	encoded, _ := json.Marshal(normalized)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func exactKeys(object map[string]strictjson.Value, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := object[key]; !exists {
			return false
		}
	}
	return true
}

func objectValue(value strictjson.Value) (map[string]strictjson.Value, bool) {
	return value.Object, value.Kind == strictjson.KindObject
}

func stringValue(value strictjson.Value) (string, bool) {
	return value.String, value.Kind == strictjson.KindString
}

func boolValue(value strictjson.Value) (bool, bool) {
	return value.Bool, value.Kind == strictjson.KindBool
}

func unsignedValue(value strictjson.Value) (uint64, error) {
	if value.Kind != strictjson.KindNumber {
		return 0, ErrInvalid
	}
	number, err := strconv.ParseUint(value.Number, 10, 64)
	if err != nil {
		return 0, ErrInvalid
	}
	return number, nil
}

func allowedString(value strictjson.Value, allowed ...string) (string, error) {
	text, ok := stringValue(value)
	if !ok {
		return "", ErrInvalid
	}
	for _, candidate := range allowed {
		if text == candidate {
			return text, nil
		}
	}
	return "", ErrInvalid
}

func referenceValue(value strictjson.Value) (string, error) {
	text, ok := stringValue(value)
	if !ok || len(text) != len("sha256:")+64 || !strings.HasPrefix(text, "sha256:") {
		return "", ErrInvalid
	}
	for _, character := range text[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return "", ErrInvalid
		}
	}
	return text, nil
}

func canonicalTimeValue(value strictjson.Value) (string, error) {
	text, ok := stringValue(value)
	if !ok || len(text) != len("2006-01-02T15:04:05Z") || !strings.HasSuffix(text, "Z") {
		return "", ErrInvalid
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != text {
		return "", ErrInvalid
	}
	return text, nil
}

func allUnique(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
