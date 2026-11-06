# Architecture &amp; Roadmap

## Why it's built this way

Three constraints shaped every decision in this repo, in order of how much
they mattered:

1. **The repo is public.** Anyone can see it, including red team and the
   other schools. That means nothing environment-specific — no hostnames,
   no IPs, no credentials, no "just for our lab" shortcuts — can ever be
   committed. Every value that's specific to a given competition comes from
   one of three places, in this priority order: an explicit `-Parameter`,
   the gitignored `config/answers.local.psd1`, or an interactive prompt.
   `modules/Common.psm1`'s `Get-CcdcAnswer` function is the single
   chokepoint that enforces this — no other file should ever call
   `Read-Host` directly or contain a literal IP/hostname/password.

2. **No live troubleshooting help on the day.** Whoever's running this
   can't necessarily get help debugging it in the moment. That means every
   module has to fail *safely and legibly* on its own: one bad host or one
   missing cmdlet must never take down the whole run, every destructive
   action needs a backup first, and every error has to say — in plain
   English, not a stack trace — what happened and roughly what to do about
   it. That's what `Invoke-CcdcSafe`, `Backup-CcdcState`, and
   `Write-CcdcLog` in Common.psm1 exist to enforce consistently, instead of
   every module reinventing its own try/catch style.

3. **It has to actually be trustworthy, not just fast.** A tool that runs
   in two minutes but might break something is worse than useless under
   competition pressure — you can't debug it live. So the bias throughout
   is: back up first, dry-run support (`-WhatIf`) everywhere, and for the
   riskiest module (firewall) a self-reverting safety net so a mistake
   heals itself instead of needing a second person at a console.

## How the pieces fit together

```
Invoke-CCDCToolkit.ps1        <- menu; you can ignore this and call modules directly too
  modules/Common.psm1          <- shared safety scaffolding, imported by everything
  modules/CcdcLogic.ps1        <- pure helpers (port tables, host matching, CIDR math,
                                  diffing, arg builders); dot-sourced by Common.psm1
  configs/threat-hunt/known-tool-names.txt  <- process names the threat hunt flags (data,
                                  not script source -- see "Antivirus" in docs/SECURITY.md)
  tests/                        <- Pester tests; run with: Invoke-Pester .\tests
  lab/                          <- dev-only practice lab (Hyper-V VMs mirroring the Windows
                                  side of the topology); see lab/README.md
  modules/Get-EnvironmentInventory.ps1
      -> writes logs/inventory-latest.json
  modules/Invoke-CredentialHardening.ps1
      -> reads inventory-latest.json (falls back to prompts)
  modules/Invoke-FirewallBaseline.ps1
      -> reads inventory-latest.json (falls back to prompts)
  modules/Invoke-ThreatHunt.ps1
      -> reads/writes logs/threat-hunt-state.json (its own state, not the inventory)
  modules/Invoke-AdminConsole.ps1
      -> writes logs/admin-console-credentials_<session>.csv on any account it creates/resets
  modules/New-IncidentReport.ps1
      -> reads session_*.log + logs/backups/ for evidence, writes logs/incident-reports/*.md
         AND a print-ready *.html memo (prep/ConvertTo-Pdf.ps1 turns that into the
         PDF the scoring engine requires)
      -> also reads logs/captures/ for packet captures taken near the incident time
  modules/Invoke-ConfigBaseline.ps1
      -> writes logs/baselines/<HOST>-baseline.json (Capture)
      -> reads it back and writes logs/baselines/verify-<stamp>.md (Verify)
      -> read-only: it never changes configuration, only records and compares it
  prep/                         <- runs on YOUR machine, never on a competition box:
                                  document -> text (reading injects), HTML -> PDF
                                  (submitting them)
  modules/Invoke-NetworkRecon.ps1
      -> reads inventory-latest.json (to flag unexpected open ports), writes logs/recon/*
  modules/Invoke-PacketCapture.ps1
      -> writes logs/captures/*.pcapng (+ .summary.txt), picked up by New-IncidentReport.ps1
  modules/Invoke-ADHardening.ps1
      -> domain-wide, not per-host (see its own section below) — writes its own credential CSV
  modules/Invoke-ExploitAudit.ps1
      -> reads configs/exploits/windows-exposures.psd1 (the catalogue; data, not code)
  modules/Invoke-DnsHardening.ps1
      -> for the AD/DNS box; reads SubnetCidr from config/answers.local.psd1 for ExpectedSubnetPrefix
  config/answers.local.psd1    <- gitignored, your filled-in prep sheet
  logs/                         <- gitignored, transcripts + backups + inventory land here
```

Run discovery first; the other modules degrade gracefully without it
(they'll just ask you for everything by hand) but work much faster with it.
The one deliberate exception is the firewall baseline, which the team has
decided (2026-10-14) to run BEFORE discovery, first thing in the round —
see `docs/RUNBOOK.md`. It specifically falls back to reading
`ScoredServices` straight from `config\answers.local.psd1` for exactly
this case (`Get-CcdcScoredServiceList` in `Common.psm1`), so it isn't
"the other modules" this line is talking about.

## Design rules for anything you add later

- Import `Common.psm1` first, call `Start-CcdcSession` before doing
  anything else.
- Never call `Read-Host` directly for environment CONFIGURATION — use
  `Get-CcdcAnswer` so the file-then-prompt fallback stays consistent
  everywhere. The one deliberate exception is a module whose entire job is
  taking fresh, one-off operational input each time it's used (the menu's
  own choice prompt; `Invoke-AdminConsole.ps1`'s "which account this
  time") — that kind of input has no business living in an answer file, so
  it uses `Read-Host` directly, the same way. If a value would plausibly
  be the same across a whole run (`DomainName`, `DefaultOU`), it still
  goes through `Get-CcdcAnswer` even inside an otherwise ad-hoc module.
- Wrap every host/account/rule-level action in `Invoke-CcdcSafe` so one
  failure doesn't kill the run, and check `.Success` / use `.Value` on
  what it returns — don't rely on the bare return value if the action
  produces a collection (see the comment on `Invoke-CcdcSafe` in
  Common.psm1 for why).
- Anything destructive: `Backup-CcdcState` first, no exceptions.
- Support `-WhatIf` (`[CmdletBinding(SupportsShouldProcess)]`) on anything
  that changes state.
- End with `Show-CcdcSummary` and `Stop-CcdcSession`.
- Never fetch-and-execute remote code at runtime (no `iwr | iex` pattern
  or equivalent) — see `docs/SECURITY.md` for why.
- Put pure logic (anything that takes values and returns a value, with no
  prompts, logging, or system calls) in `modules/CcdcLogic.ps1`, not inside
  a module script, and write a test for it in `tests/`. A function defined
  inside a script body can't be loaded without running the whole script, so
  it can't be tested — and a copy pasted into a second module drifts.
- Script files are UTF-8 **with a BOM** and LF line endings; new pure-logic
  code is ASCII-only. Windows PowerShell 5.1 (the engine the Windows
  competition boxes run) reads a BOM-less file as ANSI, and the UTF-8 bytes
  of an em dash end in 0x94, which it treats as a closing double-quote —
  every script with an em dash in a string failed to parse there until this
  was fixed. Always check with `powershell.exe`, not just `pwsh`;
  `tests\Repo.Policy.Tests.ps1` does both.
- Don't use PowerShell-7-only features (`ForEach-Object -Parallel`,
  `Test-Connection -TimeoutSeconds`, `??`, ternary). The target boxes run 5.1.
- A `-WhatIf` run must not prompt for a secret or write one to disk.
- Don't put well-known offensive-tool names in script source: antivirus
  (AMSI) reacts to them and blocked the threat hunter once as "malicious
  content". Keep such lists in a data file under `configs/`.
- A safety net that gates a risky action must be verified (read the
  registered task back and check what it will actually run as) and must
  fail closed: if it can't be armed, don't take the risky step.
- If a module creates named artifacts (firewall rules, scheduled tasks,
  anything grep-able) that would exist on the live box, pull the naming
  from the answer file (like `ArtifactPrefix`) rather than hardcoding an
  obviously-labeled string — the source is public, so a literal name is a
  free fingerprint. See `docs/SECURITY.md`.
- If a module changes something a scoring engine might depend on for a
  functional check (not just "is the port open" but "can it log in and
  do the thing"), give it an explicit protect/exclude mechanism like
  `Invoke-CredentialHardening.ps1`'s `ProtectedAccounts` — don't assume
  the operator will remember to be careful under time pressure.
- Any "did this actually work" check that gates a safety net being
  disarmed should verify real state (rule/config as applied), not a
  loopback/localhost connectivity test — Windows doesn't filter loopback
  traffic, so a localhost check can report success even when the real,
  off-box-facing rule is broken. See the firewall module's self-check for
  the pattern.

## Done

- **Incident report generator.** `modules/New-IncidentReport.ps1` —
  scaffolds a report against the six-part rubric CCDC judges actually
  score against (proof, timestamp, detection method, impact,
  remediation, prevention), and auto-searches this toolkit's own session
  logs and `Backup-CcdcState` snapshots for anything that landed near the
  incident time you give it, so the proof/timestamp sections start with
  real evidence instead of a blank page. Prevention — worth 50% of the
  rubric, as much as the other five sections combined — gets a loud
  `Write-CcdcLog -Level ERROR` warning if it's left blank, rather than
  silently shipping a report with a hole in the section worth the most
  (remediation is one of the other five, roughly 10% like each of them;
  an earlier version of this doc and of the README had that backwards). Fresh,
  one-off operational input (the six sections' answers), so it uses
  `Read-Host` directly rather than `Get-CcdcAnswer`, same as
  `Invoke-AdminConsole.ps1`. Output is Markdown under
  `logs\incident-reports\` — converting that to whatever your scoring
  portal wants (often a PDF) is still a manual step; see the module's
  own comment-based help. Pairs directly with
  `Invoke-ThreatHunt.ps1` — its output is exactly the kind of evidence
  this module's auto-search picks up.

- **Admin console.** `modules/Invoke-AdminConsole.ps1` — the tool built
  for injects, since they can ask for close to anything: a categorized
  menu (AD users/groups, local users/groups, services, scheduled tasks, a
  quick one-off firewall rule, DNS records, file/folder permissions, Group
  Policy, threat response) over the common ad-hoc admin actions, each one
  confirm-before-acting and backup-before-modifying-existing-state the
  same as every other module, plus a safety-wrapped "run a custom command"
  escape hatch (option 9) for whatever isn't covered by a purpose-built
  action — logged and error-handled the same as everything else, but with
  no auto-backup, since there's no way to know what state to save for an
  arbitrary command. Extend this one over time as real injects reveal
  what's actually needed; the escape hatch is the stopgap, not the plan.
  Threat response (option 10) is the one category that isn't inject-driven
  — it's the fast path for a team packet rule that's easy to forget under
  pressure: reactively blocking a specific malicious IP (or sinkholing a
  malicious domain via a brand-new local DNS zone) is explicitly allowed,
  but blanket-allowing only the scoring engine's IP instead of leaving
  scored ports open to Any is not — the confirmation prompt says so every
  time, since that's a one-letter-away mistake under pressure. Blocks both
  directions (inbound + outbound) rather than one port, since by the time
  you've identified a malicious IP you want it gone entirely, not just off
  one service; removal reuses the existing "remove firewall rule by name"
  / "remove DNS zone" actions rather than duplicating that logic.

- **Threat-hunt watcher.** `modules/Invoke-ThreatHunt.ps1` — strictly
  read-only (no backup step needed because nothing changes), so it's safe
  to run constantly and needs zero answer-file setup. Two layers: diffed
  checks that only report what's NEW since the last pass (state tracked in
  `logs/threat-hunt-state.json`, gitignored) — privileged AD/local group
  membership, local accounts, listening TCP ports, scheduled tasks,
  services, and registry Run/RunOnce persistence entries — and always-on
  checks that re-report every pass regardless of new-or-not — suspicious
  processes (path- or name-matched), known default C2 listener ports if
  currently listening (4444/2222 by default, flagged on sight even if not
  new), recently dropped files in common staging locations, and a
  failed/successful logon summary from the Security log. Newly-appeared
  services also get a best-effort Authenticode signature check on their
  binary, flagged alongside the existing suspicious-path check. The
  Run-key check, the always-flagged ports, and the signature check were
  added after a coach's field manual named them specifically as things
  its own hunt-loop commands watch for. The diff-based design is
  deliberate: a flat "here's everything right now" dump is useless to
  re-read every 10 minutes under time pressure, but "here's what changed"
  is exactly what's actionable.

  First run on a box always establishes a baseline with nothing to diff
  against yet — but that's NOT the same as assuming the box is clean.
  Silently folding whatever's already there into the baseline would mean
  anything red team planted before you ever got a console open just
  vanishes into "normal," permanently, since a diffed check only ever
  reports what's NEW since the pass it's comparing against. Because of
  that, the very first pass treats every diffed category as an
  UNVERIFIED one-time dump instead: a short WARN/ERROR preview per
  category in the console (via the shared `Write-CcdcInitialBaseline`
  helper), plus the full list written to
  `logs\threat-hunt-initial-baseline\<category>.txt` so nothing's lost to
  console scroll on the categories that can run long (DNS records,
  services on a box with a couple hundred installed). Services
  specifically also get the suspicious-path/signature check run against
  every currently-installed one on this first pass, not just
  newly-appeared ones — the same reasoning: a service planted before this
  tool ever ran needs the same check a newly-appeared one gets, or it's
  invisible forever. Every pass after the first goes back to pure
  diffing. This doesn't solve "tell me which of these is actually
  malicious" — nothing can, without ground truth to compare against — it
  solves "don't let the tool's own design silently hide the one pass
  where a human could still have caught it."

- **Sysmon + Splunk Universal Forwarder.** `modules/Install-Sysmon.ps1`
  and `modules/Install-SplunkForwarder.ps1` — local-host scope (see "Why
  per-host, not fleet-wide" below), not the originally-imagined
  fleet-wide push. Sysmon ships with a vendored community config
  (`configs/sysmon/`, see its own README for license/attribution);
  Splunk UF's indexer address is answer-file/prompt-sourced like
  everything else environment-specific. Both verify binary Authenticode
  signatures before running anything, and both are local-tools-folder
  first — see each module's comment-based help for exactly how binary
  staging works, and why Splunk deliberately has no auto-download option
  while Sysmon optionally does.

- **AD-specific hardening/audit module.** `modules/Invoke-ADHardening.ps1`
  — the deliberate exception to "why per-host, not fleet-wide" below,
  because domain password policy and LLMNR/NTLMv2/SMB-signing policy
  aren't per-host things to begin with. Six pieces, each independently
  `-WhatIf`-able: a stale/never-logged-in account audit (lists candidates,
  never auto-disables — you pick which ones by name, after seeing the
  list, and typing a name not on the list is skipped rather than acted
  on); a documented "blue-team admin" account added to Domain Admins and
  logged to its own credential CSV the same way every other generated
  password in this toolkit is (explicitly never meant to be secret from
  your own team — see docs/SECURITY.md); one new GPO (table-driven list
  of registry values, so the whole policy is visible at a glance) that
  disables SMB anonymous access/SAM enumeration, disables LLMNR, enforces
  NTLMv2-only, and requires SMB signing on both the client and server
  side, linked to the domain root by default; and the domain default
  password policy (length/history/lockout, current policy backed up via
  `Backup-CcdcState` first). Privileged Domain Admins/Enterprise Admins
  group membership auditing was already covered by
  `Invoke-ThreatHunt.ps1`'s existing diffed group-membership check rather
  than duplicated here. **Deliberately not built**: BloodHound/SharpHound
  collection — analyzing its output needs a separate BloodHound install,
  and whether data can even leave a NetLab+-style environment (no file
  transfer out) is still an open question for this specific setup; this
  stays a roadmap item until that's answered. Run once, from a
  domain-joined host with RSAT (ideally a DC) — unlike every other
  module here, this one is genuinely domain-wide, not scoped to the box
  it runs on.

- **Network recon (nmap) and packet capture (tshark) wrappers.**
  `modules/Invoke-NetworkRecon.ps1` and `modules/Invoke-PacketCapture.ps1`
  — added after a coach recommended both by name. nmap: three scan
  profiles (`Quick`/`Full`/`Vuln`), an optional credentialed SMB scan
  (password collected via `Read-Host -AsSecureString`, never put in the
  answer file or on nmap's command line, and written to disk only as a
  short-lived temp file that is deleted when the scan ends — see the
  external-review entry below and the transcript-leakage note under
  docs/SECURITY.md for why plain `Read-Host` isn't safe for an *existing*
  secret even though it's used elsewhere in this toolkit for fresh
  operational input), and a cross-reference against
  `logs/inventory-latest.json`'s scored-services list that flags open
  ports nothing expected. Wireshark itself is a GUI a human drives, not
  something to script — tshark, its CLI companion, is the automatable
  half, so `Invoke-PacketCapture.ps1` wraps that instead: a short,
  timestamped capture plus a protocol-hierarchy summary, matching a
  coach's field manual's "grab proof with a visible timestamp before you
  clean anything up" guidance. Both follow the same local-tools-folder-
  first staging and WARN-level (not hard-block) Authenticode signature
  check as Sysmon/Splunk, and both wrap their entire body in
  `try { ... } finally { Show-CcdcSummary; Stop-CcdcSession }` rather
  than relying on `Invoke-CcdcSafe` alone, after testing showed
  `Read-Host -AsSecureString` can fail in a way that bypasses normal
  `try/catch` entirely in a non-interactive host context — the `finally`
  block is what guarantees the transcript still closes even then.
  **Wazuh XDR agent installer was recommended alongside these two but
  deliberately not built** — whether Wazuh replaces or supplements the
  already-built Splunk Universal Forwarder module wasn't settled, so this
  stays a roadmap item pending that decision rather than being built and
  possibly conflicting with Splunk.

- **External design review, acted on.** A third-party review of the
  architecture/README/SECURITY/PREP-SHEET material (not the code itself)
  turned up one real, concrete vulnerability and several good hardening
  ideas. What got fixed:
  - **nmap credential exposure (the important one).** The credentialed
    SMB scan in `Invoke-NetworkRecon.ps1` used to pass the password
    straight to nmap via `--script-args smbuser=...,smbpass=...` on
    nmap's own command line — visible to any process listing while the
    scan ran, and, worse, captured verbatim by Sysmon's own Event ID 1
    (process creation logs the full command line by design) if Sysmon is
    deployed on the same box, which it usually is. This toolkit's own
    logging module would have forwarded a plaintext credential to
    Splunk. Fixed by switching to `--script-args-file`: the credential
    goes into a short-lived temp file instead (verified against nmap's
    own docs — same `key=value,key=value` syntax, just relocated off the
    command line), deleted in the module's `finally` block regardless of
    how the scan turns out. Only the file *path*, never its contents,
    appears in any log line.
  - **Elevation preflight.** New `Test-CcdcElevated`/`Assert-CcdcElevated`
    in `Common.psm1` — every module whose actions genuinely need admin
    rights (credential hardening, firewall baseline, Sysmon/Splunk
    install, the admin console, network recon, packet capture, AD
    hardening) now warns up front if the session isn't elevated, instead
    of failing partway through with a cryptic access-denied error. WARN,
    not a hard stop — some actions inside a module might still work
    without it, and this toolkit prefers "warn and let the operator
    decide" over a hard block wherever the outcome genuinely depends on
    what's attempted.
  - **Sensitive-folder permissions.** New `Protect-CcdcSensitiveFolder`
    restricts `logs\` (transcripts, backups, credential CSVs, captures,
    recon output) and `config\` (the local answer file) to
    Administrators/SYSTEM/the current user, via well-known SIDs rather
    than localized group names. Best-effort and honestly scoped: on a
    box where red team already has Administrator, this isn't a real
    boundary, since that's the access level being granted here too — but
    it's free, and it does stop a lower-privileged account or process on
    a shared box from reading this toolkit's own sensitive output.
  - **Admin console escape hatch.** The "run a custom command" option
    now explicitly warns that the exact command text lands in the
    plaintext session transcript — never type a password into it
    directly.
  - **`docs/RUNBOOK.md` added** — a one-page, in-order competition-day
    checklist, separate from the longer design docs, per the review's
    specific suggestion that the existing guidance was correct but
    scattered across too many long documents to use under time pressure.

  What the review raised that turned out to already be true (the
  reviewer only had the docs, not the code, so this is worth stating
  plainly rather than assuming a gap): `Backup-CcdcState` already throws
  — refusing to let a destructive action proceed — if the backup itself
  fails, rather than silently continuing; `Get-CcdcInventory` already
  warns when `inventory-latest.json` is stale (>2 hours old);
  `Invoke-FirewallBaseline.ps1` already arms its safety-net scheduled
  task BEFORE flipping the default action to Block, and only disarms it
  after verifying real rule/profile state (never a loopback check).

  What the review raised that's genuinely good but deliberately NOT
  built in this pass — logged here rather than silently dropped, same as
  every other punt in this document: automated repo-policy CI checks
  (PSScriptAnalyzer plus regex scanning for hardcoded secrets/IPs, bare
  `Read-Host`, `Invoke-Expression`/`iwr | iex` patterns) before the repo
  ever gets pushed; a formal backup manifest schema (session/host/
  operator/restore-instructions per backup, beyond the current
  timestamp+label+Clixml); a session-scoped, atomic-write artifact
  layout to fully eliminate any shared-file collision risk between
  concurrently-run modules (the current design already avoids the acute
  version of this — only `Invoke-ThreatHunt.ps1` is designed to run in
  parallel with other modules, and it owns its own separate state file —
  but a formalized layout would close the gap for good); and a
  credential-CSV lifecycle/handoff/cleanup workflow beyond "it's
  gitignored and permission-restricted." All four are real improvements,
  none of them urgent enough to justify touching a tested, working
  toolkit for right now — revisit if there's time before the repo lock
  date, or if a specific one of these actually bites.

- **Reliability round: tested on the real target engine.** A second review
  (this time of the code) plus running everything under Windows PowerShell
  5.1 — the engine the Windows competition boxes actually have — found that
  the earlier "works" checks had all been done on PowerShell 7. What it
  found, and what was done:
  - **9 of 14 scripts did not parse under Windows PowerShell 5.1** —
    including the menu and `Common.psm1` — because they were saved as UTF-8
    without a BOM and contained em dashes (see the design rule above). Every
    script now carries a BOM; `tests\Repo.Policy.Tests.ps1` fails if that
    ever regresses, and parses the whole tree with `powershell.exe`.
  - **Firewall safety net.** The revert task was registered with no
    principal, which means "current user, only while logged on, non-elevated
    token" — not enough to change firewall profiles, so the self-healing
    guarantee was doubtful, and a failed registration only logged a warning
    before the module flipped to Block anyway. Now: SYSTEM, highest run
    level, full path to `powershell.exe`, read back and verified after
    registering (a misregistered task is removed), and **fail-closed** — if
    it can't be armed, the default action is not switched to Block unless
    `-AllowNoSafetyNet` says so. `-WhatIf` no longer prints false self-check
    failures for rules it never created, and the self-check now verifies each
    rule's protocol and port, not just its name.
  - **UDP, port ranges, FTP.** Allow rules were TCP-only, so every
    UDP-carried scored service (DNS, Kerberos, LDAP locator pings, NTP)
    depended on whatever built-in rules happened to be enabled once the
    default flipped to Block. Rules are now `(protocol, port)` pairs from a
    table with both protocols; DHCP (UDP-only) had been mapped to TCP by
    mistake. Custom services accept `8443`, `8443,9443`, `50000-50100` or a
    `udp:`/`tcp:` prefix. FTP scored without a passive-mode data range now
    warns (control port 21 alone lets a login succeed while listings hang).
  - **PowerShell-7-only network sweep** in `Get-EnvironmentInventory.ps1`
    (`ForEach-Object -Parallel`, `Test-Connection -TimeoutSeconds`) silently
    did nothing on 5.1. Replaced by a concurrent .NET ping sweep that works on
    both. The CIDR math is also now correct for /31 and /32.
  - **Threat-hunt first pass** ran an `Invoke-CcdcSafe` per installed service
    (~500 log lines, inflated summary), and its console preview showed the
    first five services alphabetically instead of the flagged ones. Now the
    signature checks are quiet, flagged services are shown first (console
    and file). The offensive-tool name list moved out of the script into
    `configs/threat-hunt/known-tool-names.txt` after Windows Defender's AMSI
    blocked the script once as "malicious content" (see docs/SECURITY.md).
  - **nmap**: `-WhatIf` no longer prompts for the password or writes the
    credential temp file; the temp file has a bare-GUID name instead of a
    greppable one.
  - **Splunk**: the outputs.conf group name comes from `ArtifactPrefix`
    (was a literal `ccdc_indexers`). The installer password on msiexec's
    command line is documented and warned about but **not fixed** — see the
    roadmap.
  - **Credential rotation** with an empty `ProtectedAccounts` now stops and
    asks (type `NONE`) instead of scrolling a warning past and rotating
    everything. The menu and the domain-wide/destructive modules show a
    target-check block (host, domain, DC or not, who, elevated, inventory
    age, protected accounts) BEFORE the YES prompt.
  - **Structure and tests.** The pure logic that was trapped inside module
    scripts (two functions copy-pasted into two modules) moved into
    `modules/CcdcLogic.ps1`. `tests/` has ~150 Pester tests, including
    scripted end-to-end runs of the firewall, threat-hunt, credential, nmap/
    tshark, incident-report, admin-console, inventory, Splunk and menu flows
    against fake system data. The suite itself was mutation-checked: 23 bugs
    injected into scratch copies (safety net as the wrong user, UDP dropped,
    scored ports source-scoped, password back on the command line, gate
    removed, banner removed, ...), all caught, and the one gap that turned up
    (nothing asserted the banner names the host) got a test.
  - **Doc fixes**: the README and this file both said remediation was the
    50% rubric item; it's prevention (fixed in the code back in v8, never in
    the docs).

  What the code review raised that was deliberately NOT done: a generic
  "operations layer" of `Validate-Environment`/`Start-ArtifactAudit`-style
  wrappers (speculative), a first-class `-NonInteractive` flag on every
  module (the scripted harness in `tests/helpers/` covers the testing need;
  competition use is a human at a console), and parallelising threat-hunt or
  recon "across hosts" (both are single-host by design).

- **The window (`ui/`).** A WPF front-end, built after the numbered menu was
  tried on a real domain controller and turned out not to be the tool wanted.
  The menu is unchanged and still the way to reach everything; this is a second
  way in, aimed at the two things a list of numbers is bad at: *knowing whether
  the box is currently healthy*, and *making one small change quickly*.

  What it shows is chosen on the same principle as the rest of the toolkit —
  say what it means, and never imply certainty that isn't there. Every health
  card carries a status, a value and a sentence of what to do; "Unknown" is a
  distinct state from "Good", so a check that could not run never reads as a
  pass. The scored-services panel is the closest thing to a scoring engine you
  can run locally: it takes `ScoredServices` from the answer file, resolves the
  ports (TCP *and* UDP, custom `Port_` entries included) and reports what is
  actually listening — and says plainly that this is a local check, since a
  port can be listening while a firewall in front of it drops the traffic. An
  idle FTP passive range is reported as Unknown rather than Down, because those
  ports only open during a transfer.

  Structurally: the layout is XAML in its own file, all work runs on background
  runspaces (a window that freezes mid-round is worse than no window), buttons
  disable while something runs, every handler is wrapped so a failure lands in
  the Activity tab instead of killing the window, and the modules that ask
  questions open in their own console rather than being awkwardly wrapped. The
  work scripts are passed as text because a scriptblock belongs to the session
  that created it; they never call `Read-Host` or `Get-CcdcAnswer` (which falls
  back to a prompt), because a prompt in a background runspace hangs with
  nothing on screen to answer — `tests\Ui.Tests.ps1` enforces both rules, and
  also parses each work script, since code inside a string is invisible to the
  repo-wide parse check. That test found a real bug immediately: `$x = if (...)
  { @() }` collapses an empty array to `$null`, which had turned "nothing is
  listening" into "could not check" — an outage reported as a shrug.

  **What the first real run taught.** It crashed on the lab domain controller:
  the window flashed up and vanished, leaving a glimpse of something about
  formatting and nothing to read. Two lessons, both now fixed and both worth
  keeping in mind for anything else here:

  1. *Inside a method call's parentheses, commas separate arguments.* So
     `$box.AppendText("{0} {1}" -f $a, $b)` passes `-f` only `$a` and throws
     "Error formatting a string" the first time it runs. Building the string on
     its own line fixes it, and `tests\Repo.Policy.Tests.ps1` now fails on that
     shape anywhere in the repo.
  2. *Every test to that point checked the window's parts, not the window.* The
     layout parsed, the controls existed, the work scripts parsed — and it
     still could not start. So the script gained a `-SelfTest` switch that
     builds everything and runs one live health check without showing the
     window, and the suite runs it against a scratch copy. Reverting either fix
     is caught by it. A second bug surfaced the moment that test existed:
     `@()` around a `List[object]` of hashtables throws "Argument types do not
     match", so the work scripts now return `.ToArray()` and the consumer uses
     a bare `foreach` — either alone is enough, which is why both are there.

  Related: a failure now writes what went wrong to the transcript, shows a
  message box (only when a person is there to click it — never in `-SelfTest`,
  where a modal dialog would hang forever), and holds the console open so the
  error cannot scroll away with the process.

- **IIS / FTP audit and hardening.** `modules/Invoke-IISHardening.ps1` — the
  last big per-host gap for a Windows Admin whose scope includes a web server
  and an FTP server, which the 2026 topology says it does. Built and tested
  against the practice lab's real IIS and IIS-FTP boxes.

  The read-only audit always runs first and is the valuable half. The
  web-shell hunt is deliberately a *narrowing* tool, not a verdict: it looks
  only at files a web server would execute (plus `web.config`, which can add
  handlers), and flags them for being recently modified, sitting in a folder
  that exists to receive uploads, much newer than the rest of the site, or
  containing an indicator string. Every one of those is something legitimate
  applications also do — the point is to turn a folder of thousands of files
  into a handful to read, and the output says so. The indicator list lives in
  `configs/iis/webshell-indicators.txt` rather than in the script, for the
  same antivirus reason as the threat hunt's tool-name list (see
  docs/SECURITY.md).

  The audit also prints the exact `ScoredServices` / `Port_*` lines for the
  box, which closes a loop: IIS knows its own FTP passive data-port range, the
  firewall module needs it, and a human copying it by hand is where it gets
  missed. A `0-0` range is expanded to the real Windows ephemeral range
  (49152-65535) and warned about, since allowing 16,000 ports is worth a
  deliberate decision.

  On the changing half: directory browsing and the identifying headers are
  default-on because they are near-impossible to break anything with, and
  both are reported before they change. Request filtering by extension and
  disabling anonymous FTP are **opt-in**, because either can take down a
  scored service (a site that really does serve `.php`; a packet that really
  does score an anonymous login). Nothing changes until an IIS-native
  `Backup-WebConfiguration` has succeeded — if the backup fails the module
  stops, on the principle that it does not change what it cannot undo — and
  the exact `Restore-WebConfiguration` command is printed.

- **Practice lab kit.** With no environment to test in, everything above had
  only ever run against fakes. `lab/` builds one: `Initialize-HyperVLab.ps1`
  (run elevated on a Hyper-V host) creates an isolated virtual network and
  the Windows-side VMs (AD/DNS and IIS on Server 2019, IIS FTP on Server 2022,
  optionally Windows 11), installs Windows unattended from a per-VM answer-file
  ISO, configures the roles over PowerShell Direct with the in-VM scripts in
  `lab/guest/`, copies the toolkit in with a lab-shaped answers file, and
  takes/restores checkpoints. `lab/guest/Test-LabServices.ps1` is an outside-in
  "scoring engine" (UDP DNS, an LDAP login as the scoring account, an FTP
  login with a passive listing, ...) for proving a hardening step didn't break
  anything scored; `Add-LabIntrusionArtifacts.ps1` plants harmless red-team-
  shaped artifacts for practicing the threat hunt and incident report. The
  in-VM scripts are hypervisor-agnostic (the README has a manual/VMware route).
  Design choices worth knowing: the switch is Private (nothing can reach the
  host or the network); every VM is tagged in its Notes and later actions only
  touch tagged VMs; `Remove` needs the lab name typed; the answer-file ISO that
  carries the lab password is deleted after install. Verified without real VMs
  by running the host script against a fake Hyper-V, checking every Hyper-V call
  against the real cmdlets' parameters, and building/mounting the ISOs for real
  (the fake-Hyper-V run already caught a real bug: a missing pair of parentheses
  that broke the credential list for two of the four VMs). **Not yet run against
  real VMs** -- expect to fix a thing or two on first use.

  A side effect of reading the IIS docs to build the FTP server: the FTP
  passive data-port range is a server-level IIS setting (1025-65535, or `0-0`
  for the Windows ephemeral range 49152-65535), and behind a NAT firewall the
  FTP service may also need the firewall's external address. Both are noted in
  `docs/PREP-SHEET.md`, and the firewall module's FTP warning now mentions `0-0`.

- **Known-exploit audit.** `modules/Invoke-ExploitAudit.ps1` — the
  "what would red team try first on a deliberately unpatched box" module.
  The catalogue of exposures (what it is, what an attacker does with it,
  the exact fix, and what that fix can break) lives in
  `configs/exploits/windows-exposures.psd1` as data, not in the script
  itself — same reasoning as the threat hunt's tool-name list and the IIS
  web-shell indicators: a coach reviewing scripts can read what gets
  checked without reading PowerShell, and the catalogue can grow without
  touching logic. Covers DC-specific exposures (Print Spooler,
  `ms-DS-MachineAccountQuota`, AS-REP roasting, Kerberoasting, unconstrained
  delegation, resource-based constrained delegation, DCSync replication
  rights held outside the expected default holders, a leftover Group Policy
  Preferences password in SYSVOL, LDAP signing), credential-theft settings (WDigest, LSA protection,
  LM/NTLMv1, SMBv1, SMB signing, LLMNR, NBT-NS, anonymous enumeration), and
  local-escalation settings (AlwaysInstallElevated, unquoted service paths,
  readable SAM/SYSTEM hives, PowerShell 2.0, Guest, RDP without NLA).
  Read-only by default; `-Fix` applies only `SafeFix` catalogue entries,
  `-IncludeRiskyFixes` is a separate, deliberate opt-in for the ones that
  can need a reboot or break something depending on the weak setting.
  `-Only` re-checks specific Ids by name, for confirming a manual fix
  without re-running the whole catalogue. Deliberately scoped to
  configuration, not patch level — `Invoke-ConfigBaseline.ps1` already
  reports how far behind on updates a box is, and duplicating that here
  would just be two places to keep in sync.

- **DNS audit and hardening.** `modules/Invoke-DnsHardening.ps1` — the
  module for the AD/DNS role specifically, since DNS is simultaneously a
  scored service and the thing every other service depends on to be found,
  which makes it the worst place in the whole topology to be careless in
  either direction. The read-only audit (zones, AD-integration, dynamic
  update mode, zone transfers, recursion/forwarders/cache settings,
  records worth a human look) always runs first and runs regardless of any
  switch. Three changes are bundled as individually-safe opt-ins
  (`-SecureZoneTransfers`, `-SecureDynamicUpdates`, `-HardenCache`);
  `-DisableRecursion` is deliberately its own separate switch, never
  folded into a "harden everything" bundle, because flipping it when
  anything in the topology resolves external names through this server
  breaks that resolution and costs the DNS scored check directly — this is
  the one place in the whole toolkit where "safe default" and "what a
  real environment needs" could not both be the same answer, so the
  module forces an explicit, individual decision instead of guessing.
  Dynamic updates follow the same reasoning: `Secure` needs AD integration,
  a file-backed zone's only secure value is `None` (which stops client
  registration entirely), so a file-backed zone is reported and left
  alone rather than "fixed" into something that breaks registration.
  Deliberately complementary to, not overlapping with,
  `Invoke-ConfigBaseline.ps1`: that module fingerprints the zone FILES on
  disk (catching the rename-with-a-trailing-space attack a returning
  competitor described), this one looks at the DNS server's own settings.

### Why per-host, not fleet-wide

The original idea for this pair of modules was pushing Sysmon/Splunk to
every host in the inventory from one place. Built it per-host instead,
matching every other module: fleet-wide push needs PowerShell remoting
trust between every box (WinRM configuration, possible double-hop auth
issues) — another thing that can silently break — and a single
"orchestrator" box doing the pushing is itself a single point of failure,
which cuts against the zero-downtime goal harder than the convenience is
worth. Revisit this if it turns out to be a real bottleneck once there's
an actual host count to deal with.

## Roadmap — not built yet

Roughly in priority order. The admin console and the incident report
generator (see "Done" above) were built first and together, per a coach's
account of how a past event actually played out: keeping red team out
entirely off fully unpatched, default-credential boxes against automated
red-team tooling is treated as close to impossible, so being fast and
legible about ad-hoc changes (injects) and documenting what red team did
(incident reports) both outrank pure hardening speed as point-savers. What's
left below is scoped to what a Windows Admin still needs beyond those two.
Still treat exact commands/thresholds as a starting point, not gospel,
until confirmed against this year's rules and environment:

1. **BloodHound/SharpHound run** — flag attack paths to Domain Admin
   before red team finds them for you. Split out from the AD-hardening
   module (see "Done" above) rather than built alongside it, because it
   needs a separate BloodHound install to analyze the collected data, and
   whether that data can even leave a NetLab+-style environment (no file
   transfer out) is unconfirmed for this specific setup. Revisit once
   that's answered.

2. **Wazuh XDR agent installer** — recommended by a coach alongside nmap
   and Wireshark (see "Done" above for those). Held back specifically
   because it's unclear whether Wazuh replaces or supplements the
   already-built Splunk Universal Forwarder module for this team — that's
   normally a team/Splunk-lead call, not a Windows Admin one. Build this
   once that's settled; until then, running both side by side without
   confirming they're meant to coexist risks two agents fighting over the
   same log sources for no benefit.

3. **Linux equivalents** of credential hardening and firewall baseline
   (fail2ban, iptables/nftables/ufw/firewalld, SSH hardening, Apache/MySQL
   hardening, Postfix/Dovecot hardening) if the environment includes Linux
   boxes and nobody else on the team is covering them, or as a reference
   for reviewing what the Linux lead is doing.

4. **Splunk forwarder password off the command line.** The forwarder's
   random admin password reaches the MSI as `SPLUNKPASSWORD=...` on
   msiexec's command line (visible to process listings and, if Sysmon is
   already running, to its process-creation log; a Splunk UF management
   login is an administrative foothold). Needs a real Splunk install to
   test a fix against — candidates: seed the credential with
   `user-seed.conf` before first start, or install without the property and
   set it afterwards. Don't ship an untested change to the install path;
   try it in the lab first. Until then the module warns and the runbook
   installs the forwarder before Sysmon.

5. **Forward the Sysmon log.** The forwarder installer only enables the
   Security, System and Application event logs. Getting the Sysmon
   Operational channel into Splunk needs an `inputs.conf` stanza (or
   deployment-server config) — a team/Splunk-lead call, since it also
   depends on which add-on and sourcetype their Splunk expects.

6. **More in the window** (the first version is built — see "Done" above).
   What it does not cover yet, roughly in order of how often an inject asks
   for it: DNS records, file and folder permissions, scheduled tasks, Group
   Policy, and one-off firewall rules — all of which the admin console
   already does in text, so the work is a form per action rather than new
   logic. Worth doing at the same time: a threat-hunt tab showing findings
   in a sortable grid rather than opening a console, and an incident-report
   form (its six questions are already structured, and the evidence search
   already works). The pattern to follow is in `ui/`: pure logic in
   `CcdcLogic.ps1`, the work in a background runspace, a confirmation for
   anything destructive, and a test that the work script parses.

None of this is committed to — it's a working list. Reprioritize freely as
you learn more about what your specific regional's environment actually
looks like, and once the real rules packet is in hand, re-check every
"CRITICAL RULE"-type item above (especially source-IP restriction, see
docs/SECURITY.md) against it directly rather than assuming last year's
rules carried over exactly.
