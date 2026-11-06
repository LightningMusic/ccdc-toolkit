# CCDC Toolkit

A PowerShell toolkit for the technical (Windows Admin / Firewall Admin)
side of a CCDC blue team run: fast, safe hardening of what you're handed on
competition morning, built around three rules — back up before you touch
anything, never let one failure take down the whole run, and never
hardcode anything competition-specific because this repo is public.

See `docs/RUNBOOK.md` for a one-page, in-order competition-day checklist,
`docs/ARCHITECTURE.md` for the full design reasoning and the roadmap of
what's not built yet, `docs/SECURITY.md` for what being a public repo
actually exposes (and doesn't) plus the zero-downtime scoring-engine
gotcha, and `docs/PREP-SHEET.md` for what to fill out before you ever get
to the machines.

## Why it's structured like this

No electronics allowed in, and everything has to run from a public GitHub
repo — so nothing here can assume anything about the specific environment
you'll be dropped into, and nothing here can carry real credentials,
hostnames, or IPs in the repo itself. Every environment-specific value
comes from `config/answers.local.psd1` (gitignored — never committed) or
an interactive prompt if you didn't pre-fill it. Fill out
`docs/PREP-SHEET.md` from your scoring packet ahead of time so you're
typing answers from paper instead of hunting for them live.

## Getting it onto a box

```
git clone <this-repo-url>
cd ccdc-toolkit
```

No `git`? Download the repo as a ZIP from GitHub's web UI and extract it.
Either way, PowerShell needs to be told it's OK to run local scripts once
per machine (competition boxes are usually locked to `Restricted` by
default):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

`-Scope Process` only affects the current PowerShell window — it doesn't
change the machine's policy permanently.

## Running it

Two ways in, both fine, both talking to the same modules.

**The window** — health at a glance, whether your scored services are actually
up, and the account/service changes injects usually ask for:

```powershell
cd ccdc-toolkit
.\ui\Start-CcdcConsole.ps1
```

**The menu** — every module, including the ones the window does not cover:

```powershell
.\Invoke-CCDCToolkit.ps1
```

Press `W` in the menu to open the window; it starts in its own process, so the
menu stays usable. The window needs a desktop, so on Server Core use the menu.

That's the menu. Or call any module directly for more control — every
module supports `-WhatIf` and has full comment-based help:

```powershell
Get-Help .\modules\Invoke-FirewallBaseline.ps1 -Full
.\modules\Get-EnvironmentInventory.ps1
.\modules\Invoke-CredentialHardening.ps1 -WhatIf
```

**Recommended order on a fresh box** (the same order as `docs/RUNBOOK.md`,
team decision 2026-10-14): firewall baseline **first**, before anything
else — it reads scored services straight from the answer file, so
discovery doesn't need to run first for this to work, but the answer file
has to actually be filled in since there's no safety net catching a gap
once this is the first action of the round (it will still refuse to flip
the default to Block if it can't arm its safety net; see its help text
before you run it for real). Then discovery (read-only, so it's free, and
makes everything after this faster). Then the Splunk forwarder if you're
using one and Sysmon (low-risk, get logging running early — Splunk first,
because its install password is passed on the msiexec command line and
Sysmon would log that). Then the known-exploit audit and credential
hardening. Then AD hardening and DNS hardening if you have AD access —
both are domain-wide, one-time setup for the DC, not something you redo
per host; read DNS hardening's own warning on `-DisableRecursion` before
touching it. Then IIS/FTP audit and hardening, on whichever box has either
role. Capture a config baseline once the hardening pass above is actually
done, so `Invoke-ConfigBaseline.ps1 -Action Verify` later has a real
"right" state to compare against, not a moving target. Kick off the
threat-hunt watcher whenever, in parallel with everything else — it's
read-only and doesn't care what order it runs in relative to the others.
Run the incident report generator as soon as possible after something
happens, not at the end of the day — its auto-evidence search only has a
shot at finding the right log lines and backups if it runs while the
session log from around that time is still recent. Save network recon for
pre-competition practice runs, not the round itself (see its own module
entry below for why); packet capture is read-only evidence-gathering, so
it's safe to reach for any time you need to grab proof of something
before cleaning it up.

## What each module does

- **`ui/Start-CcdcConsole.ps1`** — the window. **Dashboard**: firewall default
  action, Sysmon and the Splunk forwarder, failed logons, listening ports,
  privileged group sizes, protected accounts, inventory age — each as a card
  with what it means and what to do — plus every service `ScoredServices` says
  is scored on this host checked against what is actually listening (a local
  check: a port can be listening while a firewall in front of it drops the
  traffic). **Accounts** and **Services** tabs for the changes an inject
  usually asks for, each confirmed, backed up and logged. **Modules** opens any
  module in its own console window. **Activity** mirrors everything into the
  session transcript. All work runs on background runspaces so the window never
  freezes; needs a desktop, so not Server Core.
- **`modules/Common.psm1`** — not run directly. Shared logging, backups,
  the answer-file/prompt system, and the "one failure doesn't kill the
  run" wrapper every other module is built on. Also restricts `logs\`
  and `config\` permissions to Administrators/SYSTEM/the current user on
  every session start, and warns any module that needs admin rights if
  the session isn't elevated — both best-effort, both non-fatal if they
  can't apply. Also holds `Show-CcdcTargetContext`, the "you are about to
  change THIS host/domain" block the menu shows before its YES prompts.
- **`modules/CcdcLogic.ps1`** — not run directly; loaded by `Common.psm1`.
  The pure, side-effect-free helpers (service-to-port tables, scored-service
  host matching, custom port specs, CIDR math, the 5.1-safe ping sweep,
  new-item diffing, evidence time windows, nmap/tshark argument builders)
  live here, in one place, so `tests\` can exercise them directly. They used
  to be private functions inside each module script (two of them
  copy-pasted), which meant they could not be tested at all.
- **`modules/Get-EnvironmentInventory.ps1`** — read-only. Finds your
  domain controllers, computers, and accounts via AD if you're
  domain-joined; falls back to a local-account check and a network sweep
  if not. Saves everything to `logs/inventory-latest.json` for the other
  modules to use automatically.
- **`modules/Invoke-CredentialHardening.ps1`** — rotates local and AD
  account passwords to fresh random values. New passwords land in a
  gitignored CSV under `logs/` — that file is the only place they're ever
  written in plaintext. A real run with an EMPTY `ProtectedAccounts` list
  stops and makes you type `NONE` (or pass `-AcknowledgeNoProtectedAccounts`)
  before it touches anything: rotating an account a scoring check logs in
  with fails that check the instant it happens.
- **`modules/Invoke-FirewallBaseline.ps1`** — builds an allow-list from
  your scored services (matched per-hostname; TCP and UDP as each service
  needs, custom ports and ranges via `Port_<Name>` in the answer file, and
  a warning if FTP is scored without its passive-mode data range) plus a
  management-access rule for RDP/WinRM from your admin subnet, then flips
  the default inbound action to Block — behind a self-reverting safety
  net (a SYSTEM-run task, read back and verified after registering) so a
  mistake here can't permanently lock your team out. If the safety net
  can't be armed, it leaves the allow rules in place and does NOT flip to
  Block unless you pass `-AllowNoSafetyNet`. Optional
  `-DisableLegacySmbRpcPorts` switch (off by default) disables — never
  deletes — pre-existing enabled rules that leave TCP 135/139 open, the
  specific ZeroLogon mitigation per a coach's field manual; see
  `docs/SECURITY.md` for why the default-block step alone doesn't close
  these on a stock Windows Server box.
- **`modules/Install-Sysmon.ps1`** — installs/reconfigures Sysmon using
  the bundled community config (`configs/sysmon/`). Local-tools-folder
  first for the binary; verifies it's genuinely Microsoft-signed before
  running it either way. One of the lower-risk modules — no firewall or
  account changes.
- **`modules/Install-SplunkForwarder.ps1`** — installs/reconfigures the
  Splunk Universal Forwarder, pointed at your indexer. Needs a `.msi`
  pre-staged in `tools/SplunkForwarder/` (see `docs/PREP-SHEET.md`) — no
  auto-download for this one, see the module's own help for why.
- **`modules/Invoke-ThreatHunt.ps1`** — read-only, changes nothing, safe to
  run constantly. One pass tells you what's NEW since the last pass
  (privileged group membership, local accounts, listening ports,
  scheduled tasks, services, registry Run/RunOnce persistence entries)
  plus what's currently suspicious regardless of new-or-not
  (processes/services/files in Temp-like paths or matching known
  offensive-tool names — kept in `configs\threat-hunt\known-tool-names.txt`,
  not in the script, because antivirus reacts to those names in script
  source — known default C2 listener ports if currently listening, recent
  failed logons); newly-appeared services also get a best-effort
  signature check on their binary. First run establishes a
  baseline, but does NOT assume the box is clean going in — everything
  each diffed check finds gets dumped once as an unverified first look
  (short WARN/ERROR preview in the console, full list under
  `logs\threat-hunt-initial-baseline\`), on the assumption red team could
  already have a foothold before you ever get a console open. Every run
  after that goes back to only flagging what's new since the last pass —
  run it again a few minutes later to start seeing diffs.
  Pass `-Continuous` in its own window to have it loop on a timer instead
  of running the menu's single pass.
- **`modules/Invoke-AdminConsole.ps1`** — the fast, one-place tool for
  ad-hoc changes an inject asks for: a categorized menu over AD/local
  users and groups, services, scheduled tasks, a quick one-off firewall
  rule, DNS records, file/folder permissions, Group Policy, and threat
  response (block a malicious IP inbound+outbound, or sinkhole a malicious
  domain to a blackhole address via a new local DNS zone — the reactive
  IP-blocking the team packet explicitly allows), all on the
  same confirm-before-acting / backup-before-changing / plain-English
  pattern as everything else. Can't cover literally everything an inject
  might ask for — option 9 is a safety-wrapped escape hatch for running a
  one-off command when nothing else fits (no auto-backup there, since
  there's no way to know what state to save for an arbitrary command —
  prefer a menu action when one exists).
- **`modules/New-IncidentReport.ps1`** — walks you through every field the
  competition actually requires. The team packet names source **and**
  destination IP addresses, timelines of activity, passwords cracked, what
  was affected, and a remediation plan; the incident-reporting inject adds
  scope, delivery mechanism, damage, and supporting evidence. It asks for
  all of it, then says which required fields are still blank rather than
  quietly producing a report with holes in it. Loudly warns if you leave
  prevention — as much as the other sections combined — empty.
  Auto-pulls session-log lines, state backups and packet captures from
  around the time you give it, so you're editing a starting draft instead
  of typing evidence from memory.
  Writes two files to `logs\incident-reports\`: a `.md` working copy and a
  print-ready `.html` business memo (the format inject guidance asks for —
  addressed to management, not to an engineer). Turn the HTML into the
  required PDF with `prep\ConvertTo-Pdf.ps1`.
  It is a form and a formatter, not a writer: inject guidance states that
  using AI tools to generate inject responses scores **zero**, so the
  words in it have to be yours.
  It also warns you off filing one at all for a misconfiguration — reports
  are scored on exploitation events, and the packet allows *negative*
  scores for frivolous or excessive reporting.
- **`modules/Invoke-ConfigBaseline.ps1`** — records what this box looks
  like when it is right, then tells you what changed. `-Action Capture` on
  a clean box, `-Action Verify` when something feels wrong. Covers DNS
  zones and their on-disk files (SHA-256), DNS server settings, services,
  scheduled tasks, local administrators and accounts, listening ports,
  firewall profiles and rules, autoruns, installed updates, and any folder
  you point `-WatchPath` at (a web root, so defacement shows up as a
  changed hash).
  It also runs a **filename tampering check that needs no baseline at
  all**, because of a specific attack a returning competitor described:
  their AD went down when a file the DNS server loads was renamed with a
  space added to the end. Nothing was deleted, nothing looked missing, and
  a zone that will not load takes the domain's SRV records with it. A
  trailing space is invisible in Explorer and in a directory listing; it is
  not invisible to a string comparison. Leading/trailing whitespace,
  trailing dots, doubled spaces, homoglyphs, text-direction overrides and
  double extensions are all reported, with the name printed in brackets so
  you can actually see it.
  AD-integrated zones are immune to that particular trick, and this tells
  you which kind you have. Read-only throughout — it changes nothing.
- **`modules/Invoke-ExploitAudit.ps1`** — checks this box against a
  catalogue of known Windows exposures (the data lives in
  `configs\exploits\windows-exposures.psd1`, not in the script, so a coach
  reviewing scripts can read the list without reading PowerShell): Print
  Spooler, print-driver installation, `ms-DS-MachineAccountQuota`
  (sAMAccountName spoofing), AS-REP roastable and Kerberoastable (SPN-bearing)
  accounts, unconstrained delegation, resource-based constrained delegation
  grants, replication ("DCSync") rights held outside the expected default
  holders, a leftover Group Policy Preferences password in SYSVOL, and LDAP
  signing on a DC; WDigest plaintext caching, LSA
  protection, LM/NTLMv1, SMBv1, SMB signing, LLMNR, NBT-NS and anonymous
  enumeration for credential theft; AlwaysInstallElevated, unquoted service
  paths, readable SAM/SYSTEM hives, PowerShell 2.0, the Guest account and
  RDP without NLA for local escalation — the published techniques red team
  reaches for first against a deliberately unpatched box. Read-only by
  default; `-Fix` applies only what the catalogue marks `SafeFix`, and the
  rest need `-IncludeRiskyFixes` plus a read of the Risk line first, since
  several (LDAP signing, LSA protection, delegation) can need a reboot or
  break something that genuinely depends on the weak setting. This is
  configuration, not patches — it only covers what you can change without a
  reboot in the first thirty minutes; `Invoke-ConfigBaseline.ps1` reports
  how far behind on patches this box actually is.
- **`modules/Invoke-NetworkRecon.ps1`** — nmap wrapper. Three scan
  profiles (`Quick`/`Full`/`Vuln`), optional credentialed SMB scan
  (password prompted via `-AsSecureString`, passed to nmap through a
  short-lived temp file — `--script-args-file`, not `--script-args` on
  the command line, which would otherwise be visible to any process
  listing and to Sysmon's own command-line logging), never written to
  disk long-term, cross-references what it finds open against your
  scored-services
  inventory and flags anything unexpected. Local-tools-folder first
  (`tools\nmap\nmap.exe`) for the binary, falls back to PATH. **Loud and
  slow — run it pre-competition to find your own holes, not during the
  round**, per a coach's field manual.
- **`modules/Invoke-PacketCapture.ps1`** — tshark wrapper (Wireshark's
  CLI companion; Wireshark itself is a GUI a human drives, not something
  to automate). Grabs a short, timestamped capture as evidence — "proof
  with a visible timestamp, taken before you clean anything up" per the
  same field manual. Local-tools-folder first (`tools\Wireshark\tshark.exe`),
  needs Npcap/WinPcap installed separately to actually capture. Captures
  taken here are found automatically by `New-IncidentReport.ps1`.
- **`modules/Invoke-IISHardening.ps1`** — for the web server and the FTP
  server. The audit half is read-only and always runs: what sites/bindings/app
  pools are here, **the exact lines to paste into your answer file** (including
  FTP's passive data-port range, which is the piece people miss until a scored
  transfer hangs), a **web-shell hunt** that narrows a web root down to the few
  executable files worth reading (recently modified, sitting in an upload
  folder, much newer than the rest of the site, or containing one of the
  indicator strings in `configs\iis\webshell-indicators.txt`), and an FTP audit
  (anonymous logins, any rule letting everyone write, new or executable-looking
  files in the FTP root). Then the changes: directory browsing off, identifying
  response headers removed. Two changes that can break a scored service are
  opt-in — `-BlockRiskyExtensions` and `-DisableAnonymousFtp`. It takes an
  IIS-native configuration backup first and prints the one command that undoes
  everything (`Restore-WebConfiguration`). Use `-ReportOnly` for the audit alone.
- **`modules/Invoke-ADHardening.ps1`** — the one deliberate exception to
  this toolkit's per-host design, because AD settings like password
  policy or LLMNR/NTLMv2/SMB-signing aren't per-host things. Six pieces:
  a stale/never-logged-in account audit (you choose what to disable, by
  name, after seeing the list), a documented blue-team admin account
  (never meant to be secret from your own team — see `docs/SECURITY.md`),
  one new GPO disabling SMB anonymous access and LLMNR and enforcing
  NTLMv2-only and SMB signing, and the domain default password policy.
  Run once, from a domain-joined host with RSAT (ideally a DC) — every
  other module here is safe to run from any box, this one isn't.
  BloodHound/SharpHound collection is deliberately not built yet — see
  `docs/ARCHITECTURE.md`'s roadmap for why.
- **`modules/Invoke-DnsHardening.ps1`** — for the AD/DNS box specifically.
  DNS is both a scored service and the thing every other service depends on
  to be found, so the read-only audit always runs first and changes
  nothing: every zone's type/AD-integration/dynamic-update mode and file,
  zone transfers (`Any server` hands over the whole zone in one request),
  server-level recursion/forwarders/cache locking/cache pollution
  protection, and records worth a human look (wildcards, TXT/NULL/HINFO,
  sub-minute TTLs, A records pointing outside your subnet — narrows
  hundreds of records to a handful, doesn't decide anything for you). Three
  changes are opt-in and safe on a normal domain controller —
  `-SecureZoneTransfers`, `-SecureDynamicUpdates` (AD-integrated zones
  only; a file-backed zone's only secure dynamic-update value is `None`,
  which stops client registration entirely, so this reports rather than
  changes those), `-HardenCache`. `-DisableRecursion` is its own switch,
  never bundled with the other three — flip it only if nothing in the
  topology resolves external names through this server, or you cost
  yourself the DNS scored check. Pairs with `Invoke-ConfigBaseline.ps1`,
  which fingerprints the zone FILES and catches a renamed one; this module
  looks at the server's settings instead.

## Practice lab

`lab\` builds a set of Hyper-V VMs that mirrors the Windows side of the
competition network (AD/DNS and IIS on Server 2019, IIS FTP on Server 2022,
optionally a Windows 11 workstation), fills it with a competition-shaped set of
users and services, and gives you checkpoints so you can try any module and undo
it in one command. It includes a "scoring engine" health check
(`lab\guest\Test-LabServices.ps1`) and a script that plants harmless red-team
artifacts for practicing the threat hunt. Dev-only; never used on a competition
box. Start with [lab/README.md](lab/README.md); from an elevated PowerShell:

```powershell
.\lab\Initialize-HyperVLab.ps1 -Action Status      # what will it use?
.\lab\Initialize-HyperVLab.ps1 -Action All         # build everything (asks for a lab password)
.\lab\Initialize-HyperVLab.ps1 -Action Restore     # undo whatever you just did to it
```

## Prep-time helpers

`prep\` holds scripts that run on **your own machine**, never on a competition
box. They exist because the paperwork side of the competition has its own file
formats.

```powershell
# Injects arrive as PDFs, and past-inject archives are a pile of PDF/.docx.
# This turns a folder of them into readable, searchable, diffable text.
.\prep\Convert-DocumentToText.ps1 -Path .\injects-archive -Recurse

# Inject responses MUST be PDF or they are not scored.
.\prep\ConvertTo-Pdf.ps1 -Path .\logs\incident-reports\WEB01_....html
```

`Convert-DocumentToText.ps1` drives Word through COM and works around the two
things that silently hang an unattended run: the modal "Word will now convert
your PDF" dialog (a per-user setting that Word reads at startup, so it has to
be set *before* Word launches), and Protected View on any file that came from
the internet (it converts an unblocked copy and never touches your original).
`ConvertTo-Pdf.ps1` uses headless Edge, then Chrome, then Word.

## Tests

```powershell
Invoke-Pester .\tests
```

About 555 tests, no install needed on Windows (they use the classic syntax of
the Pester 3.4 that ships with Windows PowerShell 5.1). They cover the pure
logic, the shared scaffolding, repo-policy rules (every script parses under
**Windows PowerShell 5.1**, scripts with non-ASCII characters carry a BOM, no
hardcoded IPs, no `iex`, no bare `Read-Host` for secrets, no `ccdc-` names, no
offensive-tool names in script source, every cmdlet parameter used anywhere
actually exists on 5.1), and scripted end-to-end runs of the firewall,
threat-hunt, credential, scanner, IIS/FTP, DNS, known-exploit, incident-report,
admin-console, inventory, lab and menu flows against fake system data in a
scratch copy of the repo. Run them (and re-run after any change) on a Windows dev machine before
you push; nothing in them touches the real firewall, accounts, or scheduled
tasks.

## Before competition day

1. Fill out `docs/PREP-SHEET.md` from your scoring packet.
2. Copy `config/answers.template.psd1` to `config/answers.local.psd1` and
   transcribe the prep sheet into it.
3. Test the whole flow — including `-WhatIf` runs of the risky modules —
   against a practice environment (a home lab VM, a spare box, whatever
   you've got) so competition day is the first time you're *using* this,
   not the first time you're *trusting* it.
4. Keep `config/answers.local.psd1` OFF of anything that leaves the venue
   with you if it ever has anything sensitive in it beyond subnet/service
   names — it's gitignored specifically so it never ends up in the public
   repo, but that's a repo-level protection, not a "this laptop is secure"
   guarantee.

## Contributing to this repo mid-competition

Since it's public, teammates can pull updates the same way you set it up
initially — `git pull` if changes get pushed during the event. Test any
change with `-WhatIf` before running it for real on a live box.

**Don't plan around this working, though.** Per a coach's account of how a
past regional ran, the public repo can get locked (frozen, no further
pushes counted) roughly a week before competition day — if that's how your
event works, nothing you push after that point exists as far as your team
on the day is concerned. Confirm the actual lock date/mechanism from your
rules packet once you have it, but until then treat "repo lock date," not
"competition day," as the real deadline: everything needs to be final and
tested well before the day itself, not the night before. See
`docs/PREP-SHEET.md` for the same point tied to a concrete timeline.
