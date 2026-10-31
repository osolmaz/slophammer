"""Rule-policy truth table and static admission tests."""

from slophammer.config import Config, MutationConfig, PythonConfig, RuleConfig, parse_config
from slophammer.core import Finding
from slophammer.repo import new_snapshot
from slophammer.rule_policy import MUTATION_RULE_ID, RulePolicy
from slophammer.rules import run_rules
from slophammer.rules.definitions import PY_MUTATION

README_RULE = "repo.readme-required"


def test_absent_false_and_empty_selection_stay_active() -> None:
    assert RulePolicy.for_check(Config()).active(README_RULE)
    assert RulePolicy.for_check(Config(), []).active(README_RULE)
    config = Config(rules={README_RULE: RuleConfig(disabled=False)})
    assert RulePolicy.for_check(config).active(README_RULE)


def test_selection_intersects_with_disablement() -> None:
    config = Config(rules={README_RULE: RuleConfig(disabled=True, reason="not required here")})
    policy = RulePolicy.for_check(config, [README_RULE])
    assert not policy.active(README_RULE)
    assert not policy.active("repo.agents-required")


def test_admission_drops_disabled_and_applies_enabled_severity() -> None:
    config = Config(
        rules={
            README_RULE: RuleConfig(disabled=True, reason="not required here", severity="warn"),
            "repo.agents-required": RuleConfig(severity="warn"),
        }
    )
    findings = [finding(README_RULE), finding("repo.agents-required")]

    admitted = RulePolicy.for_check(config).admit_all(findings)

    assert [item.rule_id for item in admitted] == ["repo.agents-required"]
    assert admitted[0].severity == "warn"


def test_disabled_static_rule_is_not_evaluated(monkeypatch) -> None:
    config = parse_config(
        "rules:\n  repo.readme-required:\n    disabled: true\n    reason: not required here\n"
    )
    policy = RulePolicy.for_check(config, [README_RULE])

    def fail_if_called(*_args: object) -> list[Finding]:
        raise AssertionError("disabled evaluator ran")

    monkeypatch.setattr("slophammer.rules.check_definition", fail_if_called)
    report = run_rules(new_snapshot("/repo", []), config, policy)

    assert report.ok
    assert report.findings == []


def mutation_config(mutation: MutationConfig | None) -> Config:
    return Config(python=PythonConfig(mutation=mutation))


def test_mutation_rule_is_off_until_opted_in() -> None:
    assert MUTATION_RULE_ID == PY_MUTATION
    assert not RulePolicy.for_check(Config()).active(PY_MUTATION)
    assert not RulePolicy.for_check(Config(), [PY_MUTATION]).active(PY_MUTATION)
    assert not RulePolicy.for_check(mutation_config(None)).active(PY_MUTATION)
    targets_only = mutation_config(MutationConfig(targets=["src"]))
    assert not RulePolicy.for_check(targets_only).active(PY_MUTATION)
    assert RulePolicy.for_check(Config()).active("py.dry-required")
    assert RulePolicy.for_check(Config()).admit_all([finding(PY_MUTATION)]) == []


def test_mutation_rule_runs_after_opt_in() -> None:
    config = mutation_config(MutationConfig(enabled=True))
    assert RulePolicy.for_check(config).active(PY_MUTATION)
    assert not RulePolicy.for_check(config, [README_RULE]).active(PY_MUTATION)


def test_disablement_wins_over_mutation_opt_in() -> None:
    config = Config(
        rules={PY_MUTATION: RuleConfig(disabled=True, reason="checked elsewhere")},
        python=PythonConfig(mutation=MutationConfig(enabled=True)),
    )
    assert not RulePolicy.for_check(config).active(PY_MUTATION)


def test_direct_policy_ignores_mutation_opt_in() -> None:
    assert RulePolicy.for_direct(Config(), [PY_MUTATION]).active(PY_MUTATION)


def test_mutation_opt_in_parses_from_config() -> None:
    enabled = parse_config("python:\n  mutation:\n    enabled: true\n").python
    assert enabled is not None and enabled.mutation == MutationConfig(enabled=True)
    default = parse_config("python:\n  mutation:\n    targets: [src]\n").python
    assert default is not None and default.mutation == MutationConfig(targets=["src"])


def finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity="error",
        path="README.md",
        message="missing",
    )
