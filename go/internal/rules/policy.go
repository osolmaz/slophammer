package rules

import "github.com/osolmaz/slophammer/go/internal/config"

// Policy owns rule selection, disablement, and effective severity for one check.
type Policy struct {
	config     config.Config
	selected   map[string]bool
	restricted bool
}

// NewPolicy builds the policy for check and check --execute.
func NewPolicy(cfg config.Config, onlyRuleIDs []string) Policy {
	selected := make(map[string]bool, len(onlyRuleIDs))
	for _, ruleID := range onlyRuleIDs {
		selected[ruleID] = true
	}
	return Policy{
		config:     cfg,
		selected:   selected,
		restricted: len(onlyRuleIDs) > 0,
	}
}

// Active reports whether the rule can run and emit findings.
func (p Policy) Active(ruleID string) bool {
	if p.restricted && !p.selected[ruleID] {
		return false
	}
	if !p.optedIn(ruleID) {
		return false
	}
	rule, configured := p.config.Rules[ruleID]
	return !configured || !rule.Disabled
}

// optedIn reports whether config enables an opt-in rule. Mutation testing is
// opt-in: go.mutation-required and its execute step stay off until
// go.mutation.enabled is true. Every other rule is on by default.
func (p Policy) optedIn(ruleID string) bool {
	return ruleID != GoMutationRequiredRuleID || p.config.Go.Mutation.Enabled
}

// Config returns the validated config used by configured rule evaluators.
func (p Policy) Config() config.Config {
	return p.config
}

// Severity returns the configured severity for an active rule.
func (p Policy) Severity(ruleID string, fallback Severity) Severity {
	rule, configured := p.config.Rules[ruleID]
	if !configured || rule.Severity == "" {
		return fallback
	}
	return Severity(rule.Severity)
}

// Admit applies policy to one finding.
func (p Policy) Admit(finding Finding) (Finding, bool) {
	if !p.Active(finding.RuleID) {
		return Finding{}, false
	}
	finding.Severity = p.Severity(finding.RuleID, finding.Severity)
	return finding, true
}

// AdmitAll applies policy to findings without changing the input slice.
func (p Policy) AdmitAll(findings []Finding) []Finding {
	admitted := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if effective, ok := p.Admit(finding); ok {
			admitted = append(admitted, effective)
		}
	}
	return admitted
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-11-01T00:51:58+08:00","module_hash":"2355f880d8862ade6d6acf09f8ed71e7dd87f3f5da613bab9440adf5d54b9009","functions":[{"id":"func/NewPolicy","name":"NewPolicy","line":13,"end_line":23,"hash":"987009576163bc6bea0c14f1c1046c34782388df20d6748ab8711e8b545f191a"},{"id":"func/Policy.Active","name":"Policy.Active","line":26,"end_line":35,"hash":"bd38cb09d1c7ab06cd02fa9208dd730cf596711a7e2448784f9b66ddcbcd231d"},{"id":"func/Policy.optedIn","name":"Policy.optedIn","line":40,"end_line":42,"hash":"e61e98bb0b74584b7f7d4c9de6c7fbbf1be506944204deb5a0e2ad769f04a5f5"},{"id":"func/Policy.Config","name":"Policy.Config","line":45,"end_line":47,"hash":"dac080e1d0f95732fd6bf38fb1214895528736e2231726730f2429fdbca2b34f"},{"id":"func/Policy.Severity","name":"Policy.Severity","line":50,"end_line":56,"hash":"8e920f217f990a440d200a6991b284271edb1c8520cac341e0e632842f1e3921"},{"id":"func/Policy.Admit","name":"Policy.Admit","line":59,"end_line":65,"hash":"be54674c718d0c4e2290e2568a12d2bf25ec2cfdca2ef53e843710670fa6bc2a"},{"id":"func/Policy.AdmitAll","name":"Policy.AdmitAll","line":68,"end_line":76,"hash":"bfc2de8dde4e813f9c629ba2d38757876681ffa2db0c02f095e4dd41468dd44e"}]}
// mutate4go-manifest-end
