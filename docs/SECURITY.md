# Threat Model

This toolkit lives in a public repo, by competition rule — nothing
brought in on a device, everything pulled from a public GitHub. That means
red team (and every other team) CAN read every line of this before the
competition even starts. Worth being precise about what that actually
exposes, instead of just feeling generally uneasy about it.

## What being public does NOT expose

**Nothing that requires network access to this repo lets anyone act
against you.** There is no listener, no webhook, no "phone home," no
remote-execution path anywhere in this toolkit — everything here is
invoked locally, by a human, on the box being defended. Red team reading
this repo cannot use it to reach into your environment. The only way this
code runs against your boxes is if someone on your team runs it there.

**Reading the source doesn't hand them working credentials or IPs.**
Nothing environment-specific is ever committed — see `docs/ARCHITECTURE.md`
for the "everything comes from a parameter, the gitignored answer file, or
a prompt" rule. The public repo, on its own, contains zero information
about your specific competition environment.

**A generic hardening script isn't secret sauce.** "Rotate default
passwords, lock down the firewall to scored ports, deploy Sysmon" is the
standard blue-team playbook, described openly in the same public CCDC
research this toolkit was built from. Red team already assumes competent
teams do this. Publishing the mechanics of *how* you do it doesn't tell
them much they didn't already expect.

## What being public DOES expose, and what's done about it

**Fingerprintable artifact names.** A rule or scheduled task with an
obvious "CCDC-" prefix, hardcoded in a public repo, is something red team
(or an automated red-team tool) can grep for by name the instant they get
any code execution on a box — and if they can find and kill the firewall
safety-net task specifically, they've disabled a defensive control you
were counting on. `Invoke-FirewallBaseline.ps1` pulls its rule/task name
prefix from `ArtifactPrefix` in the gitignored answer file instead of a
literal string, specifically so the names actually in use on the day
aren't sitting in the public source. This is a minor mitigation, not a
real security boundary — if red team already has code execution with
rights to touch a SYSTEM-run scheduled task, they've already won that box
regardless of what it's named. Treat it as one more small friction point,
not a defense to rely on.

**Knowledge of your exact defensive posture.** If red team studies this
repo closely, they know your default-deny firewall approach, that you
rotate credentials, and roughly what a Sysmon/Splunk deployment will look
like once that module exists. This is real, but it's also just... what
competent defense looks like, and it's not something obscuring the source
would meaningfully prevent — red team at the regional level has seen
plenty of teams run exactly this playbook whether or not they had this
specific repo. The actual defense against "they know your playbook" is
executing it well and fast, not hiding that you have one.

**A bug in the script becoming a self-inflicted vulnerability.** This is
the one that actually matters and is worth real engineering effort, not
just awareness: since this code runs with admin/SYSTEM rights on your own
boxes, a bug in it is a bug with admin rights. That's why every module
backs up before changing state, wraps risky actions so one failure can't
cascade, and — for the firewall module specifically — has a safety net
that assumes the change might go wrong. Keep holding new modules to that
same standard as this grows.

## Never do this, even later, even under time pressure

- **No blind remote code fetch-and-execute.** Never add a step that does
  `Invoke-WebRequest ... | Invoke-Expression` or downloads and runs a
  *script* from the internet at runtime. If a competition network's DNS
  or routing could ever be influenced by an adversary who's already on
  the network (a real category of red-team activity), a pattern like that
  turns "pull my own trusted code" into "run whatever's actually at that
  URL right now."

  `Install-Sysmon.ps1`'s optional `-AllowDownload` is the one place this
  toolkit fetches anything at runtime, and it's a deliberately narrower
  case than the rule above is about: off by default, one specific
  well-known Microsoft domain (not an arbitrary/attacker-influenceable
  URL), fetching a vendor-signed *binary* rather than a script, and its
  Authenticode signature is verified as genuinely Microsoft's before it's
  ever executed — so even a compromised/spoofed download gets refused
  rather than silently run. `Install-SplunkForwarder.ps1` deliberately has
  no equivalent option: Splunk's download flow isn't one stable,
  directly-scriptable URL the way Sysinternals' is, so automating it would
  mean either a flaky implementation or a weaker verification story, and
  neither is worth it — that module is local-tools-folder only. If you add
  a download path to a future module, hold it to the same bar: opt-in, a
  specific trusted domain, and a real integrity check before execution —
  not "no downloads ever," but never a bare fetch-and-run.
- **No real credentials, IPs, or hostnames committed, ever** — including
  in a commit message, a code comment "for reference," or test data left
  in by accident. `config/answers.local.psd1` and everything under
  `logs/` are gitignored for this reason; double-check `git status` before
  any commit if this ever does go to a real remote.
- **No secrets in generated output that isn't already gitignored.** The
  credential CSV lands under `logs/`, which is gitignored — keep it that
  way if the folder structure ever changes.

## Source-IP restriction — check your rules packet before relying on it

Some CCDC rulesets explicitly forbid restricting traffic by source IP — at
minimum for scored, publicly-facing services (the scoring engine, red team,
and orange team can all come from anywhere, and the expectation is that you
defend the service rather than dodge specific IPs). `Invoke-FirewallBaseline.ps1`
never restricts a scored port by source IP, regardless of what's in the
answer file — that's not configurable. Whether it's even OK to scope
RDP/WinRM (your own team's admin access, not a scored service) to an
`AdminSubnet` depends on how your specific ruleset is worded, and some
teams' rules read broadly enough to forbid that too. The module defaults
`AdminSubnet` to `Any` (unrestricted) for exactly this reason — it only
narrows management access if you explicitly set a real subnet in the
answer file, and its own prompt tells you to check the rules first. If
your packet is silent or ambiguous, ask White Team rather than guessing.

## ZeroLogon (TCP 135/139) — the default-block step alone doesn't close it

An ATCC coach's field manual calls out the specific mitigation: block TCP
135 and 139 from outside, separate from 445 (which stays governed by the
scored-SMB allow rule if SMB is scored on that host). Setting the default
inbound action to Block, on its own, does NOT close these on a stock
Windows Server box: built-in rule groups (File and Printer Sharing,
Network Discovery) commonly ship pre-enabled with explicit Allow rules
covering 135/139/445, and an enabled Allow rule wins over a Block default
regardless of what the default is set to. `Invoke-FirewallBaseline.ps1`
has an opt-in `-DisableLegacySmbRpcPorts` switch that finds and disables
(never deletes) currently-enabled inbound rules matching 135 or 139 —
off by default, both because it's changing pre-existing OS rules rather
than adding the toolkit's own, and because whether closing 135/139
conflicts with something your specific scored services need is a
rules-packet question, not one this toolkit can answer for you. Confirm
before turning it on for real; see the module's own comment-based help
for exactly what it does and doesn't touch.

## Read-Host and Start-Transcript — never prompt for an existing secret in plaintext

Every module's session log (`Start-CcdcSession` → `Start-Transcript`) is
plain text, gitignored but still sitting on disk in `logs\`. Confirmed by
direct testing: `Start-Transcript` captures raw console I/O, including
characters typed at a plain `Read-Host` prompt, verbatim, into that log —
type a password at a bare `Read-Host` prompt inside a transcript-wrapped
session and it shows up in cleartext in the resulting `.log` file.

This means plain `Read-Host` is fine for fresh, one-off operational input
(an account name, a menu choice, a yes/no) but must never be used to
collect an *existing* secret — one that's meaningful if someone reads it
later. Every module that generates a fresh password (credential hardening,
the admin console, the AD-hardening blue-team account) already avoids this
by never asking the operator to type one in the first place. The one place
this toolkit does need to collect an existing secret — the optional SMB
credential for `Invoke-NetworkRecon.ps1`'s credentialed scan — uses
`Read-Host -AsSecureString` instead, which does NOT get captured by the
transcript. If you add a module that ever needs to collect an existing
password, API key, or similar, use `-AsSecureString` (or avoid the prompt
entirely, e.g. by generating rather than accepting one) — never plain
`Read-Host`.

`Read-Host -AsSecureString` has its own gotcha worth knowing before you
build on this pattern: in a non-interactive host context it can fail in a
way that bypasses normal `try/catch` entirely (confirmed by direct
testing — nothing after the failed prompt runs, and no exception is
caught). It's believed to only bite when stdin isn't genuinely interactive
(scripted testing, not a real console), but the mitigation is cheap and
worth using anyway: wrap the module's entire body in
`try { ... } finally { Show-CcdcSummary; Stop-CcdcSession }`, not just
per-action `Invoke-CcdcSafe` calls, so the transcript still closes cleanly
even if that specific failure mode ever hits for real.
`Invoke-NetworkRecon.ps1` and `Invoke-PacketCapture.ps1` both do this.

## Command-line arguments are not a safe place for a secret either

A related but distinct leak: a child process's command-line arguments
are visible to anything on the box that can list processes — Task
Manager's command-line column, `Get-CimInstance Win32_Process`, and
Sysmon's own Event ID 1, which logs the full command line by design
(that's the whole point of it, for catching attacker activity). If this
toolkit's own Sysmon deployment is running, as it usually is, anything
passed as a plaintext credential on another process's command line gets
captured and potentially forwarded to Splunk right alongside everything
else — a self-inflicted exposure through the toolkit's own logging.

This was a real bug, not a hypothetical: `Invoke-NetworkRecon.ps1`'s
credentialed SMB scan used to pass the password to nmap via
`--script-args smbuser=...,smbpass=...`, putting it directly on nmap's
command line. Fixed by switching to nmap's `--script-args-file` option —
the credential goes into a short-lived temp file instead (same
`key=value,key=value` syntax, just relocated off the command line),
deleted in a `finally` block regardless of how the scan turns out. If
you ever add a module that shells out to an external tool with a
credential, check whether that tool has an equivalent
file-based/stdin-based argument option before reaching for a
command-line flag — most well-designed CLI tools that accept credentials
do, specifically for this reason.

### Known remaining case: the Splunk forwarder's install password

`Install-SplunkForwarder.ps1` still passes the forwarder's random admin
password to the MSI as `SPLUNKPASSWORD=...`, which puts it on msiexec's
command line for the length of the install — the same class of exposure as
the nmap bug above. It is not fixed because the fix (seeding the credential
with `user-seed.conf`, or setting it after install) has to be tested against a
real Splunk install, and an untested change to the install path is a bigger
risk than the exposure it removes. What limits it: the password is random,
single-use and specific to that one forwarder; the module prints a warning
before installing; and `docs/RUNBOOK.md` installs the forwarder BEFORE Sysmon,
so Sysmon isn't already logging process creation when it happens. It is still
worth treating as an open item (see the roadmap in `docs/ARCHITECTURE.md`):
a Splunk universal forwarder's management login is an administrative foothold.

### Also by design: generated passwords are printed for the operator

Several modules generate a password and immediately show it to you on screen
(`Invoke-AdminConsole.ps1` on create/reset, the AD-hardening blue-team
account) so you can hand it to a teammate or an inject. Because the session
transcript records console output, those passwords also end up in the
`logs\session_*.log` file, in addition to the credential CSV. Both live under
the permission-restricted `logs\` folder; neither is ever committed. Treat the
whole `logs\` folder as sensitive, not just the CSV.

## Antivirus (AMSI) and the offensive-tool name list

Windows Defender scans PowerShell script text through AMSI, and it reacts to
well-known offensive-tool names appearing in that text. This toolkit's
threat-hunt module has a list of such names — the tools it exists to notice —
and on one first run the script was blocked outright ("This script contains
malicious content and has been blocked by your antivirus software"), because
its own indicator list looked like the real thing. It was not reproducible on
later runs (Defender's cloud verdict on a never-seen file, most likely), which
is what makes it dangerous on a competition box: it fails at the worst moment
and only sometimes.

So the names live in `configs/threat-hunt/known-tool-names.txt`, a plain data
file the script reads, not in script source, and
`tests\Repo.Policy.Tests.ps1` fails if a well-known name appears in any
script. If a script is ever blocked this way on a competition box: do NOT
disable antivirus or hunt for a bypass — that's a rules question and a
security regression. Tell your coach/White Team, and check whether anything
other than the tool-name list is being matched. As a pre-push safeguard,
`tests\Repo.Policy.Tests.ps1` also runs every script's text through AMSI
(scanned, never executed) and fails on a detection; that only reflects the
signatures on the machine running the tests, so it can't promise the same
verdict on a competition box, but it catches the obvious cases.

## The practice lab (lab/) — what it is and isn't

`lab/` is a dev-only kit for building throwaway VMs; it is not part of what runs
on a competition box, and being in the public repo exposes nothing about your
real environment (it uses lab names and 10.10.10.x documentation addresses, and
no real credentials). Things worth knowing anyway:

- The lab's network is a Private virtual switch, so the deliberately weak
  lab (every account has the same known password; harmless "intrusion"
  artifacts can be planted) is unreachable from your LAN and your host.
- The lab admin password is prompted for as a SecureString and never stored by
  the toolkit, but the unattended-install answer file has to carry it in plain
  text; that small ISO is deleted once Windows is installed, and only lives on
  the host disk until then. Use a throwaway password, never a real one.
- `Add-LabIntrusionArtifacts.ps1` plants inert artifacts that look like what a
  threat hunt looks for (a listener on 4444, a Run key, an extra Domain Admin).
  Defender may object; that's fine, don't disable it to run the exercise.
- The lab's scripts are exempt from the "no `ccdc-` names" and "no
  `Invoke-WebRequest`" policy tests (the in-VM folder is `C:\ccdc-toolkit`, and
  the health check GETs a page from the lab web server); everything else in
  `tests\Repo.Policy.Tests.ps1` still applies to them.

## Zero-downtime — the uptime/scoring risk that's easy to miss

Firewall changes and credential rotations are the two things in this
toolkit most likely to cause an actual outage if done carelessly — see
each module's own comment-based help for the specific mitigations
(`Get-Help .\modules\Invoke-CredentialHardening.ps1 -Full` and the
firewall module's `.PARAMETER`/self-check section). The short version:
some scoring packets check service *functionality* by logging in with a
specific account, and rotating that account's password without reporting
the new value through your packet's required channel breaks the check
immediately — that's why `ProtectedAccounts` exists, and why a real run of
`Invoke-CredentialHardening.ps1` with that list empty stops and makes you
type `NONE` rather than letting a warning scroll past. The firewall module
verifies rule/profile state (not a loopback ping, which Windows doesn't
even filter) before trusting a change enough to disarm its own safety net,
and it verifies the safety net itself (a SYSTEM-run task, read back after
registering) before it will flip the default action to Block at all.

Also worth knowing for the same reason: with the default inbound action on
Block, only what has an enabled Allow rule keeps working. The firewall module
creates TCP and UDP rules for the standard services, and takes custom ports
and ranges from the answer file, but it can't know about a service's
secondary ports (FTP passive data ports are the classic one; it warns about
that specifically). If a scored service has a second port range, list it as
its own entry — see `docs/PREP-SHEET.md`.

The same principle applies to `Invoke-ADHardening.ps1`'s documented
"blue-team admin" account: it's added to Domain Admins and logged to a
credential CSV the same way every other generated password in this
toolkit is, and the module says so out loud when it creates it. A secret
admin account nobody but its creator knows about is a liability on a
team, not an asset — if that one person is unavailable when the team
needs Domain Admin access fast (during an active incident, say), an
undocumented account helps nobody. Share it with your team through
whatever channel you'd use for any other credential, the same day it's
created.
