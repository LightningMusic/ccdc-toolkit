# Competition-Day Runbook

One page, in order. Everything here is explained in more depth elsewhere
(`README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`,
`docs/PREP-SHEET.md`) — this page exists so you're not hunting through
those under time pressure. Print it or keep it open in a second window.

## Before you touch a box

- [ ] `docs/PREP-SHEET.md` is filled out and transcribed into
      `config/answers.local.psd1` — **this is non-negotiable now.** The team
      has decided the firewall baseline runs FIRST, before discovery, so
      there is no safety net catching a missing value live: `ScoredServices`,
      every `Port_<Name>` override, `Port_FTPPassive` if FTP is scored,
      `AdminSubnet`, and `ArtifactPrefix` all need to already be correct in
      the answer file before round start, or the very first action of the
      round runs with gaps. Do a practice dry-run of this exact order before
      relying on it live — this sequencing is new and has not been run for
      real yet.
- [ ] `tools\Sysmon\`, `tools\SplunkForwarder\`, `tools\nmap\`,
      `tools\Wireshark\` are staged with the binaries you'll need (see
      `docs/PREP-SHEET.md` for exact download links/paths).
- [ ] You know your rules packet's answer on source-IP restriction (see
      `docs/SECURITY.md`) — don't guess this live.

## On the box, in order

1. **Verify elevation and execution policy.** `Set-ExecutionPolicy
   -Scope Process -ExecutionPolicy Bypass`, then confirm you're running
   as Administrator — every state-changing module now warns up front if
   you're not, but it's faster to just start elevated.
2. **Start the toolkit.** `.\Invoke-CCDCToolkit.ps1` — this starts the
   session transcript and creates `logs\`/`config\` (permission-
   restricted automatically). Press **W** for the window if this box has a
   desktop: its dashboard tells you in one look whether the firewall is
   default-block, whether logging is running, and whether the services your
   packet scores are actually listening. Keep it open and hit Refresh
   whenever you want to know the box is still healthy.
3. **[5] Run firewall baseline** (after previewing with **[4]**), **first,
   before anything else** — team decision, 2026-10-14. It reads
   `ScoredServices` straight from `config\answers.local.psd1` when
   `logs\inventory-latest.json` doesn't exist yet (it falls back
   automatically — confirmed in the module's own code), so discovery does
   NOT need to run first for this to work, as long as the answer file is
   actually filled in. Read its own WARN lines before typing YES. It only
   flips the default to Block if it could arm AND verify its self-reverting
   safety net; if it says it couldn't, the allow rules are in but nothing
   was blocked — read the error, fix it, re-run (or use
   `-SkipDefaultBlock`). If FTP is scored, make sure the passive data range
   is set (it warns; see `docs/PREP-SHEET.md`), or a login can succeed
   while listings hang — there is no later IIS/FTP audit step to catch this
   for you anymore, since that now runs after.
4. **[1] Run environment discovery.** Read-only, free — everything else
   works better with `logs\inventory-latest.json` populated.
5. **Confirm scored services and protected accounts** in
   `config\answers.local.psd1` match what discovery found and what your
   packet says. This is the single most consequential thing to get right
   before you touch credentials — a wrong `ProtectedAccounts` list can fail
   a functional check the instant you rotate a password. If discovery finds
   a mismatch against what the firewall baseline already used in step 3,
   re-run the firewall baseline too.
6. **[7] Install/update Splunk forwarder** if you're using one, then
   **[6] Install/update Sysmon** — get logging running early, before
   anything risky. Splunk first on purpose: its install password is passed
   on msiexec's command line, and Sysmon would log that.
7. **[3] Run credential hardening** (after previewing with **[2]**). The
   menu shows the host/domain it's about to change first — read it. If
   `ProtectedAccounts` is empty it stops and asks you to type `NONE`;
   that's the safeguard working, so fix the list unless you're sure.
8. **[19] Known-exploit audit**, then **[20]** to close the safe gaps.
   Read-only first pass, same pattern as everything else here. `-Fix`
   (menu **[20]**) only applies what the catalogue marks safe; a handful of
   riskier ones (LDAP signing, LSA protection, delegation) need a deliberate
   `-IncludeRiskyFixes` run from a console, not the menu's default path —
   read the Risk line for each before doing that.
9. **[14] AD hardening & audit**, if you have AD access — do this once,
   early, since it's domain-wide setup, not a per-host thing you redo.
10. **[21] DNS audit**, then **[22] DNS hardening**, on the AD/DNS box.
    Read-only first; the three bundled changes
    (`-SecureZoneTransfers -SecureDynamicUpdates -HardenCache`) are safe on
    a normal domain controller. **Do not pass `-DisableRecursion`** unless
    you are certain nothing in the topology resolves external names through
    this server — see the module's own warning, and `docs/DNS-FIELD-GUIDE.md`
    if DNS still feels unfamiliar.
11. **[15] IIS/FTP audit**, on the web server and the FTP server. Read-only,
   so it costs nothing. Two things to act on: the answer-file lines it prints
   (especially `Port_FTPPassive` — put it in `config\answers.local.psd1` and
   re-run the firewall baseline, or scored FTP transfers will hang), and any
   file it flags under a web root. Then **[16]** to apply the hardening.
   Capture evidence BEFORE deleting anything it finds.
12. **[17] Capture a config baseline**, now that the hardening pass above is
    actually done. This is what gives **[18] Verify** something real to
    compare against later instead of a moving target — do this LAST of the
    hardening steps, not first.
13. **[9] Start threat-hunt watching**, in its own window, running
   continuously (`.\modules\Invoke-ThreatHunt.ps1 -Continuous` called
   directly, not through the menu). Its first pass is NOT a clean-slate
   guarantee — read that first pass's output once, it may be showing you
   something already there.
14. **[12] Network recon** — pre-competition practice only, never during
    a live round (it's loud and slow, and looks like exactly the traffic
    you're supposed to be hunting for).

## During the round

- **[10] Admin console** for anything an inject asks for that isn't
  automatic. Read the warning before using option 9 (custom command) —
  never type a password directly into it, it gets logged. Its own option
  10 (threat response) is the fast path to block a malicious IP or
  sinkhole a malicious domain the moment you've identified one — reactive
  blocking like this is explicitly allowed by the packet; allow-listing
  only the scoring engine's IP instead is not, and the prompt says so.
- **[13] Packet capture** the moment you catch something, BEFORE you
  clean it up — timestamped proof is worth real points.
- **[11] Write an incident report** as soon as possible after handling
  something, not at the end of the day, so its auto-evidence search
  still has recent session-log lines and backups to find. Prevention is
  worth half the recoverable points on the six-part rubric — don't leave
  it blank.

## If something goes wrong

- **A script is blocked as "malicious content"** (antivirus/AMSI): don't
  disable antivirus. Tell your coach / White Team. See the "Antivirus"
  section of `docs/SECURITY.md`.
- **A scored web or FTP service broke after IIS hardening**: undo the whole
  lot in one step with the `Restore-WebConfiguration -Name '<name>'` command
  that module printed, then re-run it with `-ReportOnly` and apply the pieces
  one at a time.
- **A parse error the moment you start it, on `powershell.exe`**: this copy
  of the repo probably lost its file encoding (the scripts need their UTF-8
  BOM under Windows PowerShell 5.1). Re-clone or re-extract it rather than
  editing files in place on the box.
- **The firewall module refused to flip to Block**: that's the safety-net
  check working — the allow rules are in place. The error above the message
  says why; fix it and re-run.
- **DNS stopped resolving external names after hardening**: you (or someone)
  passed `-DisableRecursion` to `Invoke-DnsHardening.ps1`. `Set-DnsServerRecursion
  -Enable $true` on the DC turns it back on immediately — this is reversible,
  not a backup-restore situation.
- **You're not sure you're on the right box**: the target-check block the
  menu shows before each YES prompt names the host, domain, whether it's a
  domain controller, and who you're running as.

## End of session / end of day

- [ ] Anything genuinely sensitive that landed under `logs\` or
      `config\answers.local.psd1` — credential CSVs especially — gets
      handled per your team's evidence/handoff process, not left
      sitting on a shared box longer than it needs to be.
- [ ] If you're handing off to a teammate, tell them the blue-team admin
      account name (from AD hardening) and where the credential CSVs are
      — none of this is meant to be a secret from your own team.
