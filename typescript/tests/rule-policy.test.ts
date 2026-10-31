import { describe, expect, it } from "vitest";

import { emptyConfig, loadConfig, type Config, type RuleConfig } from "../src/config/config.js";
import { newSnapshot } from "../src/repo/repo.js";
import { RulePolicy } from "../src/rules/policy.js";
import { runRules } from "../src/rules/rules.js";
import type { Finding } from "../src/rules/types.js";

const readmeRule = "repo.readme-required";

describe("RulePolicy", () => {
  it("keeps absent and false disablement active", () => {
    expect(RulePolicy.defaults().active(readmeRule)).toBe(true);
    expect(
      new RulePolicy(configWithRules(ruleConfigs([[readmeRule, { disabled: false }]]))).active(
        readmeRule
      )
    ).toBe(true);
  });

  it("intersects selection with enabled rules", () => {
    const policy = new RulePolicy(
      configWithRules(ruleConfigs([[readmeRule, { disabled: true, reason: "not required here" }]])),
      [readmeRule]
    );

    expect(policy.active(readmeRule)).toBe(false);
    expect(policy.active("repo.agents-required")).toBe(false);
  });

  it("drops disabled findings and applies enabled severity", () => {
    const rules = ruleConfigs([
      [readmeRule, { disabled: true, reason: "not required here", severity: "warn" }],
      ["repo.agents-required", { severity: "warn" }]
    ]);
    const policy = new RulePolicy(configWithRules(rules));
    const admitted = policy.admitAll([finding(readmeRule), finding("repo.agents-required")]);

    expect(admitted).toEqual([
      expect.objectContaining({ rule_id: "repo.agents-required", severity: "warn" })
    ]);
  });

  it("does not evaluate a disabled static rule", () => {
    const config = configWithRules(
      ruleConfigs([[readmeRule, { disabled: true, reason: "not required here" }]])
    );
    const report = runRules(newSnapshot("/repo", []), config, new RulePolicy(config, [readmeRule]));

    expect(report).toEqual({ ok: true, findings: [] });
  });
});

describe("mutation opt-in", () => {
  const mutationRule = "ts.mutation-required";

  it("keeps the mutation rule off until typescript.mutation.enabled", () => {
    expect(RulePolicy.defaults().active(mutationRule)).toBe(false);
    expect(RulePolicy.defaults([mutationRule]).active(mutationRule)).toBe(false);
    expect(RulePolicy.defaults().active("ts.dry-required")).toBe(true);
    expect(RulePolicy.defaults().admitAll([finding(mutationRule)])).toEqual([]);
    expect(
      new RulePolicy(withMutation({ enabled: false, targets: ["src"] })).active(mutationRule)
    ).toBe(false);
  });

  it("arms the mutation rule after typescript.mutation.enabled", () => {
    const optedIn = withMutation({ enabled: true, targets: [] });

    expect(new RulePolicy(optedIn).active(mutationRule)).toBe(true);
    expect(new RulePolicy(optedIn, ["repo.readme-required"]).active(mutationRule)).toBe(false);
  });

  it("lets reasoned disablement win over the opt-in", () => {
    const optedIn = withMutation({ enabled: true, targets: [] });
    const disabled = {
      ...optedIn,
      rules: ruleConfigs([[mutationRule, { disabled: true, reason: "checked elsewhere" }]])
    };

    expect(new RulePolicy(disabled).active(mutationRule)).toBe(false);
  });

  it("ignores the opt-in for direct commands that skip config", () => {
    expect(new RulePolicy(emptyConfig(), [mutationRule], false).active(mutationRule)).toBe(true);
  });

  it("parses the opt-in from slophammer.yml", () => {
    const parse = (content: string): Config =>
      loadConfig(newSnapshot("/repo", [{ path: "slophammer.yml", content }]));

    expect(parse("typescript:\n  mutation:\n    targets: [src]\n").typescript.mutation).toEqual({
      enabled: false,
      targets: ["src"]
    });
    expect(parse("typescript:\n  mutation:\n    enabled: true\n").typescript.mutation).toEqual({
      enabled: true,
      targets: []
    });
    expect(() => parse('typescript:\n  mutation:\n    enabled: "yes"\n')).toThrow(
      "typescript.mutation.enabled must be a boolean"
    );
  });
});

describe("rule policy config", () => {
  it("rejects non-boolean disablement", () => {
    const snapshot = newSnapshot("/repo", [
      {
        path: "slophammer.yml",
        content: 'rules:\n  repo.readme-required:\n    disabled: "true"\n'
      }
    ]);

    expect(() => loadConfig(snapshot)).toThrow(
      "rules.repo.readme-required.disabled must be a boolean"
    );
  });

  it("rejects whitespace-only reasons", () => {
    const snapshot = newSnapshot("/repo", [
      {
        path: "slophammer.yml",
        content: 'rules:\n  repo.readme-required:\n    disabled: true\n    reason: " "\n'
      }
    ]);

    expect(() => loadConfig(snapshot)).toThrow("reason is required");
  });
});

function ruleConfigs(
  entries: readonly (readonly [string, RuleConfig])[]
): ReadonlyMap<string, RuleConfig> {
  return new Map(entries);
}

function configWithRules(rules: Config["rules"]): Config {
  return { ...emptyConfig(), rules };
}

function withMutation(mutation: Config["typescript"]["mutation"]): Config {
  const config = emptyConfig();
  return { ...config, typescript: { ...config.typescript, mutation } };
}

function finding(ruleID: string): Finding {
  return {
    rule_id: ruleID,
    severity: "error",
    path: "README.md",
    message: "missing"
  };
}
