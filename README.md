# Agent Access Review

[![Checks](https://github.com/pradap/agent-access-review/actions/workflows/checks.yml/badge.svg)](https://github.com/pradap/agent-access-review/actions/workflows/checks.yml)

**Understand what changed before giving an agent new access.**

Agent Access Review compares two MCP configuration files, explains supported access changes, and applies your team's review rules. It wraps the open-source [mcp-audit](https://github.com/cruxet/mcp-audit) scanner for additional checks. Everything runs locally or in GitHub Actions; no model API, account, or database is needed.

```text
Scope expanded: docs
Before: /project/docs
After:  /project
Team rule: Review required.
```

See the [complete example report](examples/expanded-report.md).

## Try the first release

Requires Python 3.10+. From a checkout of this repository:

```sh
python3 -m agent_access_review examples/before.json examples/expanded.json
```

This returns **exit 2** because the configured folder scope expands. The corrected example passes:

```sh
python3 -m agent_access_review examples/before.json examples/fixed.json
```

To include the scanner, install the pinned dependency (Node.js 18+ and npm required):

```sh
npm ci --ignore-scripts --no-audit --no-fund
python3 -m agent_access_review examples/before.json examples/expanded.json \
  --policy .agent-review/policy.json \
  --scanner node_modules/.bin/mcp-audit \
  --output output/review.md
```

The dependency is **@cruxet/mcp-audit 0.2.0**, the published release tested by this project. Its upstream source may advertise a newer unpublished version. The scanner is optional, explicitly invoked, and never downloaded automatically by the Python tool. Without `--scanner`, the report clearly says scanning was not run. Package installation requires network access; review execution does not.

For structured output, add `--format json`. To install the CLI locally, use `python3 -m pip install .` in a virtual environment, then `agent-access-review before.json after.json`.

## What v0.1 does

- Identifies added and removed servers.
- Explains expanded, narrowed, or changed roots for recognized filesystem server configurations.
- Flags exact npm package versions changed to floating or unspecified versions.
- Flags other changed fields without pretending to infer their permissions.
- Applies configurable team rules and an optional scanner severity threshold.
- Produces Markdown or JSON, with a fingerprint of the proposed configuration.
- Emits GitHub run summaries and downloadable reports in the included workflow.

**This release does not verify human approval, implement exceptions, enforce runtime permissions, or certify safety.** A failed check remains failed until the proposed configuration is corrected or a separately reviewed policy change alters the rule. Approval identities, expiring exceptions, and reusable cross-repository installation are future work.

## Supported configuration

Strict JSON with a top-level `mcpServers` object (and optional `$schema`). Each server must have exactly one `command` or `url`; `args` must be a string array, and `env` / `headers` string maps. Unknown per-server fields are retained and changes require review by default. Unsupported top-level formats, duplicate keys and malformed input are errors, not a clean result.

Filesystem interpretation is deliberately narrow: `command: "npx"`, an optional `-y` or `--yes`, the exact package `@modelcontextprotocol/server-filesystem` with an optional version, and absolute POSIX root paths. Other launchers, relative paths, variable expansion and Windows paths receive a generic configuration-change finding. Paths are compared lexically; symlinks, server-supplied roots, ACLs and actual runtime behavior are not resolved. Example package versions are illustrative configuration data and the filesystem server is never installed or launched.

A configured server's existence does not reveal its database privileges or whether it can read or write. Server renames appear as removal plus addition. Existing unsupported configurations are not audited by the change engine; enabling the scanner adds its separate checks.

## Team rules

Edit [.agent-review/policy.json](.agent-review/policy.json). `true` means a change requires review; `false` makes that category informational. Omitted rule keys retain defaults. Unknown keys or invalid types fail validation.

| Rule | Default |
| --- | --- |
| Server added | Review |
| Folder scope expanded or otherwise changed | Review |
| Package no longer exactly pinned | Review |
| Other configuration fields changed | Review |
| Folder scope narrowed | Informational |
| Server removed | Informational |

Scanner findings at or above `scanner_fail_on` (default `high`) also require review. They include pre-existing findings in the proposed configuration; they are not presented as newly introduced. Raw scanner evidence is deliberately not copied into reports. Scanner parse errors, unsupported output, diagnostics or process failures are errors. We rely on the scanner's own rules and cannot guarantee it detects every problem.

Exit codes: **0** = no review required by the configured checks; **2** = review required; **1** = input, scanner or operational error.

## GitHub workflow

[Checks](.github/workflows/checks.yml) runs unit tests plus both real-scanner examples. Its expected outcome is that expanded access needs review and the corrected example passes.

For pull requests, a separate **Agent access review** check compares the base and proposed `.mcp.json`. The review implementation, dependency lock and policy come from the trusted base commit. Proposed configuration is read as data, never launched. Review output appears in the Actions summary and as an artifact retained for 14 days. Raw input configurations are not uploaded as artifacts. No PR comments are posted.

In this repository the workflow is ready to run. To enforce it as a merge gate, a maintainer must configure a branch rule requiring **Agent access review**. A failing check alone does not prevent a merge without that rule. Protect workflow and policy changes with code review as well; a contributor-controlled workflow is not a tamper-proof security boundary. Use a separate trusted workflow or organization rules for stronger enforcement.

## Privacy and results

Environment values, headers, URL values, commands and arbitrary argument values are omitted. Known environment/header values are additionally redacted from display fields. Reports include server names, changed field names, recognized filesystem roots and a configuration fingerprint: these can reveal internal information, so inspect reports before sharing publicly. This is targeted redaction, not a general secret detector. Raw scanner output is processed in memory and not persisted by the wrapper.

Rules are versioned in Git. Reports live in local `output/` (ignored by Git), GitHub summaries and short-lived artifacts. We do not yet store approval decisions.

## Development

```sh
python3 -m unittest discover -s tests -v
npm ci --ignore-scripts --no-audit --no-fund
python3 scripts/check_examples.py
```

No Python runtime dependencies. Tests cover scope interpretation, unknown formats, policy validation, redaction, scanner failures and CLI exit codes.

## Roadmap

1. Validate reports with real configuration changes and reviewers.
2. Add reusable installation into another repository.
3. Add authenticated review decisions tied to the exact configuration and expiring exceptions.
4. Expand supported client formats and scanner adapters using tested contracts.

MIT licensed. The separately installed mcp-audit scanner is also MIT licensed; its dependencies retain their own licenses. This project is independent of the scanner maintainers.
