# CCDC Competition Compendium

*Everything compiled to date on Elijah's Collegiate Cyber Defense Competition (CCDC) prep: competition structure, team context, rules/constraints, the target network environment, and the ccdc-toolkit built for it. Compiled 2026-09-28. This intentionally excludes the practice-lab build/troubleshooting work itself — only the environment it's meant to mirror is included below.*

---

## 1. Competition Format & Structure

- CCDC (Collegiate Cyber Defense Competition) is not run on physical hardware in the room. Elijah's team connects over the internet through a portal/stadium-style setup (his coach described something like a NetLab+-style environment) to remote terminals/VMs — once connected, it behaves like an ordinary remote-desktop session, not local hardware access.
- There is no copy-paste or file upload between a competitor's own machine and the target VMs (unless VMware Tools happens to be present on that VM). Anything needed on a box has to originate from the team's public GitHub repo and be cloned or typed in by hand on the box itself.
- Research basis: early prep was built around the winterknight.net "How to Win CCDC" blog series (used to understand competition structure and pick a role), plus a "coach told him CCDC rules don't usually change year to year" — so prep has been proceeding off 2025 rules/materials while the 2026 rules packet is still pending.
- His team's first meeting was 2026-09-15. As of the latest update, the actual 2026 rules packet, role assignments, and tool choices had not yet arrived — several planning items below are explicitly flagged as provisional until that packet lands.

### Reference materials on file
Uploaded by Elijah and factored into the toolkit's design (content of these isn't reproduced here, just logged as sources actually used):
- Windows Hardening Guide (2025 Midwest Invitational team materials)
- Linux Hardening Guide (same source)
- CCDC Blue Team Strategy (same source)
- LDAP/AD & Email Services Guide (same source)
- PrestaShop/MySQL Guide (same source)
- "ATCC CCDC Field Manual" (from a coach) — this is what specifically drove the nmap/Wireshark(tshark)/Wazuh/AD-hardening asks

## 2. Team Role & Strategic Context

- Elijah wants (and is building toward) the **Windows Admin** seat — the heaviest scripting role on the team. As of 2026-09-27 **no one on the team has been assigned a role yet**; Elijah is the strongest candidate for Windows Admin and is building on that assumption.
- Motivating vision: an "ultimate admin tool" inspired by a former coworker's Microsoft 365 admin executable — something that did many AD/Windows admin tasks other tools couldn't, run off admin credentials, and could make **any** ad-hoc AD/system change fast without hunting for the right raw command under time pressure, since injects can require literally anything unpredictable.
- Design philosophy: many small modular tools invoked from one menu/entry point, rather than one large fragile all-in-one executable — reduces the chance of a single break taking everything down on competition day. Toolkit is meant to only ever grow (features added, never removed).
- **Zero downtime is a non-negotiable requirement** for his team, per Elijah's own industry experience.
- Strategic framing from a coach who has done the competition for several years:
  - Keeping red team out entirely is treated as near-impossible — boxes start fully unpatched with default credentials, and red team runs automated scripts from the start.
  - Besides hardening as fast as possible, **documenting how/where/what red team did** (via injects and incident reports) is a major, and possibly *more* important, point recoverer than raw hardening speed.
  - The team has accepted they likely won't "win" outright against red team, and are planning realistically around that.
- Unresolved team-level strategic call: when red team gets a foothold, take the box offline immediately and eat the downtime to harden it, vs. try to win the race by swapping credentials fast while staying live. This is a team decision, not Elijah's alone, and is still undecided.

## 3. Competition Rules & Constraints (as currently understood)

- **No electronics/devices allowed into the competition space.**
- **Every script must run from a public (non-private) GitHub repo** — nothing environment-specific can be hardcoded into it; environment values (hostnames, IPs, accounts) must be entered via a local, pre-filled config or interactive prompts instead.
- The public repo may get **locked/frozen roughly a week before competition day** (per the coach) — this is still being reconciled against Elijah's earlier plan to hold off publishing until just a few days out; the timeline will need replanning once confirmed by the actual rules packet.
- A **coach reviews/approves scripts before use**. Workflow: each teammate can push to their own individual GitHub, but has to send scripts to the coach for review.
- **No copy-paste or file transfer** from a competitor's own machine into the target VMs (confirmed by the coach as a real, known trip-up for past teams, not hypothetical) — unless VMware Tools is present.
- Plan for environment-specific config: stage answer/config files locally on the host machines, typed in once per box from a prepared prep sheet — since that's local typing on the box, not something requiring copy-paste across the remote connection.
- Elijah has separately flagged (in the toolkit's SECURITY.md, pending confirmation against the real rules packet) that CCDC rulesets often forbid source-IP restriction outright, at least for scored services — his firewall module respects this by never scoping restrictions onto scored ports.
- Two ideas were raised and explicitly **not** adopted pending the real rules packet, both flagged as risky: a secret local admin account nobody else knows about (audit/backdoor-appearance risk if undocumented from teammates), and pulling toolkit config live from a private GitHub repo during the round (rules-violation and credential-exposure risk).
- Public-repo exposure risk: because the toolkit repo will eventually be public, red team (industry professionals) could read its source to learn or evade the team's defenses, or exploit the tool itself — this is treated as a real threat the toolkit's own design has to account for (see SECURITY.md items below), not just a theoretical concern.

## 4. Target Network Environment (2026 CCDC Topology)

This is the actual environment topology shared from a 2026 team briefing slide — the thing the practice lab is meant to mirror, independent of how the practice lab itself has been built:

- **Router:** VyOS
- **Two firewalled network segments**, split by vendor:
  - **Palo Alto side:**
    - Ecom — Ubuntu 24
    - Webmail — Fedora 42
    - Splunk — Oracle Linux 9
    - Wkst — Ubuntu 24
  - **Cisco FTD side** — this is Elijah's side as Windows Admin:
    - AD/DNS server — Windows Server 2019
    - Web server — Windows Server 2019
    - FTP server — Windows Server 2022
    - Workstation — Windows 11

This topology is the target spec his practice lab (and the ccdc-toolkit's testing) has been reshaped around — a Windows Admin-side roster of router + AD/DNS (Server 2019) + Web (Server 2019) + FTP (Server 2022) + Windows 11 workstation.

## 5. The ccdc-toolkit

Local-only PowerShell toolkit (not yet pushed to any remote — deliberately kept local until closer to competition, per the exposure-risk reasoning above). Built sporadically, picked back up after practice meetings as Elijah learns more about the actual rules and role. Development principle: **only ever add features, never remove existing ones.**

### Built modules (through v11)

| Module | Purpose |
|---|---|
| `Common.psm1` | Logging, backup, and safety helpers shared by every module; also holds the elevation preflight (`Test-CcdcElevated`/`Assert-CcdcElevated`, added v10); v11 adds the target-check banner (`Show-CcdcTargetContext`) and the trimmed, null-safe `Read-CcdcInput` |
| `CcdcLogic.ps1` (v11) | The pure, side-effect-free helpers (service-to-port tables incl. UDP, scored-service host matching, custom port specs, CIDR math, a Windows PowerShell 5.1-safe ping sweep, new-item diffing, evidence time windows, nmap/tshark argument builders), dot-sourced by `Common.psm1` so `tests\` can exercise them |
| `Get-EnvironmentInventory.ps1` | AD / local / network discovery |
| `Invoke-CredentialHardening.ps1` | Bulk password rotation, self-generates strong random passwords |
| `Invoke-FirewallBaseline.ps1` | Firewall lockdown with a self-reverting safety net; scopes management-only ports (RDP/WinRM) via `-RemoteAddress`, never scopes scored ports; optional `-DisableLegacySmbRpcPorts` switch for the ZeroLogon-relevant TCP 135/139 mitigation |
| `Invoke-CCDCToolkit.ps1` | Menu / entry point for everything |
| `lab\` (v12, dev-only) | A practice-lab kit: `Initialize-HyperVLab.ps1` builds isolated Hyper-V VMs mirroring the Windows side of the topology (LABDC AD/DNS + LABWEB IIS on Server 2019, LABFTP IIS FTP on Server 2022, optional Windows 11), installs Windows unattended, configures roles over PowerShell Direct with the in-VM scripts in `lab\guest\`, copies the toolkit in with a lab answers file, and does checkpoint/restore. Includes `Test-LabServices.ps1` (an outside-in "scoring engine": UDP DNS, LDAP login as the scoring account, HTTP/HTTPS, FTP login with a passive listing) and `Add-LabIntrusionArtifacts.ps1` (plants harmless red-team-shaped artifacts). See `lab\README.md` |
| `Install-Sysmon.ps1` | Per-host Sysmon install; local-tools-folder-first with Authenticode signature verification; Sysmon config vendored from SwiftOnSecurity/sysmon-config (CC BY 4.0, attributed) |
| `Install-SplunkForwarder.ps1` | Per-host Splunk Universal Forwarder install (per-host by design, to avoid a WinRM-trust/single-orchestrator single point of failure) |
| `Invoke-ThreatHunt.ps1` (menu 9) | Read-only watcher; diffs current state against its own last pass — privileged group membership, local accounts, listening ports, scheduled tasks, services, registry Run/RunOnce keys, GPO modification times, DNS records. Always re-flags suspicious processes/files/logon activity and known C2 ports (4444/2222) regardless of new-or-not. First pass dumps every diffed category as an explicit unverified baseline (short console WARN/ERROR preview + full list to `logs\threat-hunt-initial-baseline\<category>.txt`) rather than silently treating pre-existing state as clean — closes a gap Elijah spotted himself where red-team persistence already present on first run would never register as "new." |
| `Invoke-AdminConsole.ps1` (menu 10) | The "one place for any ad-hoc change" tool — categorized menu over AD/local users+groups, services, scheduled tasks, one-off firewall rules, DNS records, file/folder permissions, Group Policy, plus a safety-wrapped escape hatch for an arbitrary command when nothing else fits (loudly warns it logs to the plaintext transcript — never type a password into it) |
| `New-IncidentReport.ps1` (menu 11) | Scaffolds an incident report against the six-part CCDC scoring rubric — proof / timestamp / detection / impact / remediation / prevention (prevention weighted 50%, corrected in v8 after being backwards) — auto-pulls matching session-log lines and state backups as starting evidence, loud warning if remediation is left blank |
| `Invoke-NetworkRecon.ps1` | nmap wrapper — Quick/Full/Vuln profiles, optional credentialed SMB scan, cross-checks open ports against the scored-services inventory. Credentialed scan passes the password via nmap's `--script-args-file` (a short-lived temp file, deleted after the scan) rather than on the command line, after a real bug was found where the plaintext password would otherwise land in process listings and in the toolkit's own Sysmon command-line logging |
| `Invoke-PacketCapture.ps1` | tshark wrapper (Wireshark itself is GUI-only, not scriptable) — short timestamped captures kept as evidence, auto-discovered by the incident report generator |
| `ui\Start-CcdcConsole.ps1` (v14, menu option W) | **The window Elijah asked for.** WPF, dark, runs from a .ps1 (no exe). Dashboard: health cards (firewall default action, Sysmon/Splunk, failed logons, listening ports incl. known remote-access ports, privileged group sizes, protected accounts, inventory age) each with a status/value/what-it-means, plus every scored service for this host checked against what is actually listening (TCP and UDP, custom `Port_` entries, idle FTP passive ranges reported honestly). Accounts tab (list/reset/disable/enable/add-to-group/create, AD or local; passwords generated, never typed, written to `logs\ui-credentials_*.csv`). Services tab (list/filter/start/stop/restart/startup type, flags binaries in unusual paths). Modules tab opens any module in its own console. Activity tab mirrors everything into the session transcript. All work on background runspaces so it never freezes; needs a desktop (not Server Core) |
| `Invoke-IISHardening.ps1` (v13, menu 15 audit / 16 harden) | For the Web and FTP servers. Read-only audit (always runs): sites/bindings/app-pool identities, the exact `ScoredServices`/`Port_*` lines to paste into the answer file **including FTP's passive data-port range**, a web-shell hunt over executable files under each web root (flagged for recent modification, sitting in an upload folder, being much newer than the rest of the site, or containing an indicator string from `configs\iis\webshell-indicators.txt`), and an FTP audit (anonymous logins, everyone-can-write rules, new/executable files in the FTP root). Changes: directory browsing off, X-Powered-By and Server headers removed. Opt-in only: `-BlockRiskyExtensions`, `-DisableAnonymousFtp`. Takes an IIS-native `Backup-WebConfiguration` first and refuses to change anything if that fails; prints the one `Restore-WebConfiguration` command that undoes it all |
| `Invoke-ADHardening.ps1` (menu 14, gated by a "Type YES" confirmation) | Domain-wide by design (the one deliberate exception to per-host scope): stale/never-logged-in account audit (operator picks what to disable, by name), a documented non-secret blue-team admin account added to Domain Admins, a new GPO disabling SMB-anonymous/LLMNR and enforcing NTLMv2/SMB-signing, and the domain default password policy |

### Explicitly NOT built (logged as roadmap, not silently dropped)
- Wazuh XDR agent installer — held pending whether it replaces or supplements the existing Splunk Universal Forwarder deployment; Elijah's own answer was "not sure yet / not my call" (a team/Splunk-lead decision)
- BloodHound / SharpHound collection — unconfirmed whether data can leave a NetLab+-style environment at all
- Linux-equivalent modules
- Automated repo-policy CI / PSScriptAnalyzer checks (partly done in v11: local Pester repo-policy tests in `tests\`; still no CI on GitHub and no PSScriptAnalyzer)
- Splunk forwarder install password still passes on msiexec's command line (documented and warned about; the fix needs a real Splunk install to test — see `docs/ARCHITECTURE.md` roadmap)
- Forwarding the Sysmon log to Splunk (the forwarder installer only enables Security/System/Application; a team/Splunk-lead call)
- More in the window: DNS records, file/folder permissions, scheduled tasks, Group Policy, one-off firewall rules, a threat-hunt findings grid and an incident-report form (the first version shipped in v14; the admin console still covers all of these in text)
- A formal backup-manifest schema
- A fully session-scoped/atomic-write artifact layout
- A credential-CSV lifecycle/handoff workflow

### Security posture built into the toolkit
- Elevation preflight warns upfront which modules need admin rights, instead of failing partway through
- Best-effort NTFS permission restriction on `logs\` and `config\` (Administrators/SYSTEM/current user only)
- Any module using `-AsSecureString` is wrapped in try/finally around its whole body (a bug was found where `Read-Host -AsSecureString` can fail in a way that bypasses try/catch entirely in a non-interactive host)
- `docs/SECURITY.md` documents that `Start-Transcript` captures plaintext `Read-Host` input verbatim into the session log — any future prompt for an *existing* secret must use `-AsSecureString`, never a bare `Read-Host`
- `docs/RUNBOOK.md` — a one-page, in-order competition-day checklist, separate from the longer design docs
- A third-party architecture review was triaged against the actual code (not accepted blindly): several flagged "open questions" turned out to already be handled (backup already refuses to proceed on failure, inventory already warns on stale data, firewall module already arms its safety net before the risky change). One genuinely serious bug the review did catch — the SMB-scan plaintext-password issue above — was fixed.

### Practice-lab status (v12, built for real 2026-09-27)
Elijah's host (Windows 11 Pro, 64 GB RAM, Hyper-V, VMware Workstation also installed) has the Server 2019 and 2022 evaluation ISOs in Downloads (no Windows 11 ISO yet). **The lab built successfully on the first real run** — 24 of 24 steps in about 23 minutes — giving LABDC (AD/DNS), LABWEB (IIS) and LABFTP (IIS FTP) on an isolated network, with a `clean-baseline` checkpoint on each. It must be run from an elevated PowerShell (the assistant's session is not elevated, so Elijah runs it). One rough edge found and fixed: both member servers failed their first domain join because a DC answers PowerShell Direct before AD DS is really serving DNS/LDAP; the guest scripts now wait for the domain locator record and a real LDAP connection first. The lab is where every module should be validated before competition day.

### Toolkit build history (version notes)
- **v1:** Common.psm1, Get-EnvironmentInventory.ps1, Invoke-CredentialHardening.ps1, Invoke-FirewallBaseline.ps1, Invoke-CCDCToolkit.ps1 (menu)
- **v2:** ProtectedAccounts safeguard, real-state firewall self-check, configurable ArtifactPrefix, docs/SECURITY.md threat model
- **v3:** Install-Sysmon.ps1 and Install-SplunkForwarder.ps1 (per-host), local-tools-folder-first with signature verification, vendored Sysmon config
- **v4:** Incorporated the 5 uploaded 2025 reference docs; fixed a real bug where `Invoke-FirewallBaseline.ps1`'s AdminSubnet value was logged but never actually applied; documented the source-IP-restriction rules question; sharpened the roadmap with concrete detail from the reference docs
- **v5:** Built Invoke-ThreatHunt.ps1 (menu 9)
- **v6 (doc-only):** Reprioritized the roadmap per the coach's framing (incident report generator moved to top); documented repo-lock-timing risk and the no-clipboard/typed-git-clone constraint
- **v7:** Built Invoke-AdminConsole.ps1 (menu 10) and New-IncidentReport.ps1 (menu 11); fixed real bugs found via execution testing (console rendering bugs in the admin console; a millisecond-drift bug and a bad `Read-Host ''` call in the incident report generator)
- **v8:** Built off the ATCC field manual; fixed the incident-report rubric weighting bug (prevention is 50%, not remediation); extended threat-hunt with registry persistence diffing, C2 port flagging, service signature checks, GPO/DNS diffing; added `-DisableLegacySmbRpcPorts`; built Invoke-NetworkRecon.ps1 and Invoke-PacketCapture.ps1; built Invoke-ADHardening.ps1; fixed two more bugs found via execution testing (an empty-string `-replace` bug, and the `Read-Host -AsSecureString` try/catch bypass)
- **v9:** Fixed the threat-hunt first-pass gap Elijah spotted himself — verified end-to-end with faked AD/GPO/DNS/network cmdlets simulating red team already present (rogue Domain Admins member, backdoor local admin, suspicious-path service); pass 1 correctly surfaced all three, pass 2 correctly showed only new deltas
- **v10:** Triaged a long third-party architecture review against actual code; fixed the nmap credentialed-scan plaintext-password bug; added the elevation preflight, NTFS permission restriction, stronger admin-console warning, and docs/RUNBOOK.md
- **v11:** Reliability round, tested on the real target engine (Windows PowerShell 5.1, not just PowerShell 7). Found and fixed: 9 of 14 scripts failed to parse under 5.1 (UTF-8 without a BOM + em dashes; every script now has a BOM); the firewall safety-net task had no principal (now SYSTEM/Highest, verified after registering, fail-closed unless `-AllowNoSafetyNet`); allow rules were TCP-only (now TCP+UDP, custom ports/ranges, FTP passive-range warning, DHCP mapping fixed, `-WhatIf` false failures gone, self-check checks protocol/port); a PowerShell-7-only network sweep (now a 5.1-safe ping sweep); threat-hunt first-pass noise and misleading preview; nmap `-WhatIf` and temp-file name; Splunk output-group fingerprint; docs that had remediation/prevention backwards. Added a hard stop when credential rotation runs with an empty `ProtectedAccounts`, and a target-check banner (host/domain/DC/user/elevation/inventory age) before the menu's YES prompts. Moved the offensive-tool names out of the threat-hunt script into `configs/threat-hunt/known-tool-names.txt` after Windows Defender's AMSI blocked the script once as "malicious content". Extracted the pure logic to `modules/CcdcLogic.ps1` and added ~150 Pester tests (`tests\`), including scripted end-to-end runs of the firewall, threat-hunt, credential, nmap/tshark, incident-report, admin-console, inventory, Splunk and menu flows, plus repo-policy tests; the suite was mutation-checked (23 injected bugs, all caught). Not fixed, only documented: the Splunk installer password on msiexec's command line.
- **v15:** Fixed the window's first real outing — on the lab DC it opened and closed instantly with a glimpse of a formatting error. Cause: `$box.AppendText("{0}{1}" -f $a, $b)` — inside a method call the commas belong to the method, so `-f` got one argument and threw. Fixes: build the string separately; a repo-policy test that fails on that shape anywhere; a `-SelfTest` switch that builds the whole window and runs a live health check without showing it, run by the suite against a scratch copy (every earlier UI test checked the window's *parts*, which is why a runtime crash got through). That self-test immediately exposed a second bug (`@()` around a `List[object]` throws) and the fact that the new error message box would hang a headless run. Also: lab ISO discovery now searches `-IsoSearchPath`, Downloads, and the folder of any ISO named explicitly — Elijah's Windows 11 Enterprise Evaluation ISO (image index 1) turned out to live at `D:\E_Drive_Preserved\Lab Deployment\install_media\`, alongside both Server ISOs, with a deleted copy still in the Recycle Bin.
- **v14:** Built the window (`ui\Start-CcdcConsole.ps1`, menu option W) after Elijah tried the numbered menu on the real lab DC and said it wasn't what he was looking for — he wants a UI that looks good and has useful features. WPF from a .ps1, no exe, so the coach can still review it. The two things a numbered list is bad at: knowing whether the box is healthy right now (dashboard + a local scored-services check) and making one small change fast (Accounts/Services tabs). Reliability: background runspaces so it never freezes, buttons disable while busy, every handler wrapped, destructive actions confirmed and backed up, everything mirrored to the transcript. Tests parse the work scripts (code inside strings is invisible to the repo parse check), check every named control exists in the XAML, and load the XAML for real in an STA runspace — which caught a real bug where `$x = if (...) { @() }` collapses to `$null`, turning "nothing is listening" into "could not check".
- **v13:** Built `Invoke-IISHardening.ps1` (menu 15 audit / 16 harden) — the last big per-host gap, now that the topology confirms a Web server and an FTP server on the Windows Admin side and the lab has both to test against. Read-only audit first (web-shell hunt, answer-file lines including the FTP passive range, FTP audit), then low-risk changes, with the two service-breaking changes opt-in and an IIS-native backup that must succeed before anything changes. Indicator strings live in `configs\iis\webshell-indicators.txt` (same antivirus reasoning as the threat-hunt tool names). Fixed the lab's domain-join race found in the first real build. ~253 tests; the IIS tests run the real module against a stand-in WebAdministration module and real files on disk.
- **v12:** Practice-lab kit (`lab\`, see above) because there was no environment to test in. Built with the Microsoft docs as a reference (unattended-install settings, `Install-ADDSForest`, IIS FTP passive-port configuration, PowerShell Direct); the unattended install targets image index 2 (Desktop Experience), read from the real ISOs. Testing: the helper module and ISO builder are covered directly; the host script runs against a fake Hyper-V (which caught a real credential-list bug); a new repo-wide policy test checks every cmdlet parameter used anywhere against the real cmdlets' definitions on Windows PowerShell 5.1 (it catches PowerShell-7-only parameters and typos); 12 injected bugs in the lab code were all caught. Also: the firewall module's FTP warning and the prep sheet now note that IIS FTP's passive range may be `0-0` (the Windows ephemeral range 49152-65535) and may need the firewall's external IP when behind NAT. ~200 tests total.

## 6. Open Items Pending the Real Rules Packet

- Final confirmation of Elijah's role (Windows Admin is his stated goal, not yet formally assigned)
- Whether source-IP restriction is actually forbidden for scored services
- The exact repo-lock timing, and how that reshapes the publish-timeline plan
- Whether to keep the toolkit fully local until "just a few days before" competition, or some other publish timeline
- The team-level decision on take-offline-and-harden vs. stay-live-and-swap-credentials when red team gets in
- Whether Wazuh XDR gets built (depends on the Splunk-lead's call)
- Whether BloodHound/SharpHound collection is even permissible in-environment
