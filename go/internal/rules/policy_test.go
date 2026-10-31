package rules

import (
	"context"
	"testing"

	"github.com/osolmaz/slophammer/go/internal/config"
	"github.com/osolmaz/slophammer/go/internal/repo"
)

func TestPolicyKeepsAbsentAndFalseDisablementActive(t *testing.T) {
	if !NewPolicy(config.Config{}, nil).Active(ReadmeRequiredRuleID) {
		t.Fatal("unconfigured rule is inactive")
	}
	cfg := config.Config{Rules: map[string]config.RuleConfig{
		ReadmeRequiredRuleID: {Disabled: false},
	}}
	policy := NewPolicy(cfg, nil)
	if !policy.Active(ReadmeRequiredRuleID) {
		t.Fatal("explicit false rule is inactive")
	}
	if severity := policy.Severity(ReadmeRequiredRuleID, SeverityError); severity != SeverityError {
		t.Fatalf("severity = %q, want fallback %q", severity, SeverityError)
	}
}

func TestPolicyIntersectsSelectionWithDisablement(t *testing.T) {
	cfg := config.Config{Rules: map[string]config.RuleConfig{
		ReadmeRequiredRuleID: {Disabled: true, Reason: "not required here"},
	}}
	policy := NewPolicy(cfg, []string{ReadmeRequiredRuleID})
	if policy.Active(ReadmeRequiredRuleID) {
		t.Fatal("disabled selected rule is active")
	}
	if policy.Active(AgentsRequiredRuleID) {
		t.Fatal("unselected rule is active")
	}
}

func TestPolicyDropsDisabledFindingsAndAppliesEnabledSeverity(t *testing.T) {
	cfg := config.Config{Rules: map[string]config.RuleConfig{
		ReadmeRequiredRuleID: {Disabled: true, Reason: "not required here", Severity: "warn"},
		AgentsRequiredRuleID: {Severity: "warn"},
	}}
	findings := NewPolicy(cfg, nil).AdmitAll([]Finding{
		{RuleID: ReadmeRequiredRuleID, Severity: SeverityError},
		{RuleID: AgentsRequiredRuleID, Severity: SeverityError},
	})
	if len(findings) != 1 || findings[0].RuleID != AgentsRequiredRuleID {
		t.Fatalf("findings = %#v", findings)
	}
	if findings[0].Severity != SeverityWarn {
		t.Fatalf("severity = %q, want warn", findings[0].Severity)
	}
}

func TestPolicyKeepsMutationOffUntilOptedIn(t *testing.T) {
	off := NewPolicy(config.Config{}, nil)
	if off.Active(GoMutationRequiredRuleID) {
		t.Fatal("mutation rule is active without go.mutation.enabled")
	}
	if !off.Active(GoCRAPRequiredRuleID) {
		t.Fatal("non-opt-in rule is inactive without go.mutation.enabled")
	}
	targetsOnly := config.Config{Go: config.GoConfig{Mutation: config.MutationConfig{Targets: []string{"internal"}}}}
	if NewPolicy(targetsOnly, []string{GoMutationRequiredRuleID}).Active(GoMutationRequiredRuleID) {
		t.Fatal("mutation targets alone opted in, want go.mutation.enabled")
	}
	findings := off.AdmitAll([]Finding{{RuleID: GoMutationRequiredRuleID, Severity: SeverityError}})
	if len(findings) != 0 {
		t.Fatalf("findings = %#v, want mutation finding dropped", findings)
	}

	optedIn := config.Config{Go: config.GoConfig{Mutation: config.MutationConfig{Enabled: true}}}
	if !NewPolicy(optedIn, nil).Active(GoMutationRequiredRuleID) {
		t.Fatal("mutation rule is inactive with go.mutation.enabled")
	}
	optedIn.Rules = map[string]config.RuleConfig{
		GoMutationRequiredRuleID: {Disabled: true, Reason: "checked by another job"},
	}
	if NewPolicy(optedIn, nil).Active(GoMutationRequiredRuleID) {
		t.Fatal("disabled mutation rule is active after opt-in")
	}
}

func TestRunWithPolicyDoesNotCallDisabledRule(t *testing.T) {
	called := false
	rule := countingRule{called: &called}
	cfg := config.Config{Rules: map[string]config.RuleConfig{
		ReadmeRequiredRuleID: {Disabled: true, Reason: "not required here"},
	}}

	report := RunWithPolicy(
		context.Background(),
		repo.NewSnapshot("/repo", nil),
		[]Rule{rule},
		NewPolicy(cfg, []string{ReadmeRequiredRuleID}),
	)

	if called {
		t.Fatal("disabled evaluator ran")
	}
	if !report.OK || len(report.Findings) != 0 {
		t.Fatalf("report = %#v", report)
	}
}

type countingRule struct {
	called *bool
}

func (r countingRule) Metadata() Metadata {
	return Metadata{ID: ReadmeRequiredRuleID, Severity: SeverityError}
}

func (r countingRule) Check(context.Context, repo.Snapshot) []Finding {
	*r.called = true
	return []Finding{{RuleID: ReadmeRequiredRuleID, Severity: SeverityError}}
}
