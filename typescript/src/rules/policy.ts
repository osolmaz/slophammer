import { emptyConfig, type Config } from "../config/config.js";
import { ruleIDs } from "./definitions.js";
import type { Finding, Severity } from "./types.js";

/** Owns rule selection, disablement, opt-in, and effective severity for one check. */
export class RulePolicy {
  private readonly selected: ReadonlySet<string> | undefined;

  public constructor(
    private readonly config: Config,
    onlyRuleIDs: readonly string[] = [],
    private readonly honorConfig = true
  ) {
    this.selected = onlyRuleIDs.length === 0 ? undefined : new Set(onlyRuleIDs);
  }

  /** The policy of a repository without slophammer.yml. */
  public static defaults(onlyRuleIDs: readonly string[] = []): RulePolicy {
    return new RulePolicy(emptyConfig(), onlyRuleIDs);
  }

  public active(ruleID: string): boolean {
    const selected = this.selected === undefined || this.selected.has(ruleID);
    const enabled =
      !this.honorConfig ||
      (this.config.rules.get(ruleID)?.disabled !== true && this.optedIn(ruleID));
    return selected && enabled;
  }

  public anyActive(ruleIDs: ReadonlySet<string>): boolean {
    return [...ruleIDs].some((ruleID) => this.active(ruleID));
  }

  public severity(ruleID: string, fallback: Severity): Severity {
    return this.config.rules.get(ruleID)?.severity ?? fallback;
  }

  public admit(finding: Finding): Finding | undefined {
    if (!this.active(finding.rule_id)) {
      return undefined;
    }
    return {
      ...finding,
      severity: this.severity(finding.rule_id, finding.severity)
    };
  }

  public admitAll(findings: readonly Finding[]): readonly Finding[] {
    return findings.flatMap((finding) => {
      const admitted = this.admit(finding);
      return admitted === undefined ? [] : [admitted];
    });
  }

  /**
   * Mutation testing is opt-in: ts.mutation-required and its execute step
   * stay off until typescript.mutation.enabled is true. Every other rule is
   * on by default.
   */
  private optedIn(ruleID: string): boolean {
    return ruleID !== ruleIDs.tsMutationRequired || this.config.typescript.mutation.enabled;
  }
}
