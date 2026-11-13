# CCDC Prep Sheet

Print this (or copy it into whatever you're allowed to bring in on paper)
and fill it out from your team's scoring packet BEFORE competition day.
Everything on this sheet maps directly to a value the toolkit will ask you
for — having it ready means you're typing from a sheet instead of hunting
for the answer mid-competition.

Once you've filled this out by hand, transcribe it into
`config/answers.local.psd1` (copy `config/answers.template.psd1` first) so
you only have to type it once per box, not once per module per box.

## Domain / network basics

- Domain name (`DomainName` in the answer file — also used by the admin
  console for new users' UPNs and as the default DNS zone): ______________________
- Domain controller hostname(s): ______________________
- Default OU for new AD users (`DefaultOU` — optional, blank = AD's own
  default location), e.g. `OU=Users,DC=domain,DC=local`: ______________________
- Your admin/management subnet (the one your team's boxes live on, NOT
  "any"): ______________________ /____
- If no domain (workgroup boxes): subnet to sweep for discovery, CIDR
  form (e.g. 10.10.10.0/24): ______________________

## Scored services

Copy this straight from the scoring packet. One row per scored
service-on-a-host.

| Hostname | Service | Standard port? (Y/N) | Port if custom |
|----------|---------|-----------------------|-----------------|
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |
|          |         |                       |                 |

Standard services the toolkit already knows the port for: DNS, LDAP,
Kerberos, HTTP, HTTPS, SMB, RDP, WinRM, FTP, SSH, SMTP, POP3, IMAP, MSSQL,
DHCP, NTP. Anything else, write the port down.

Once filled in, this whole table becomes ONE line in
`answers.local.psd1`:

```
ScoredServices = 'DC01:DNS,DC01:LDAP,WEB01:HTTP,WEB01:HTTPS,WEB01:CustomApp'
```

(and one `Port_CustomApp = '8443'` line per custom/non-standard service.)

The standard services are opened on the right protocols for you (DNS,
Kerberos and LDAP on both TCP and UDP; NTP and DHCP on UDP only), so you only
write down what the toolkit doesn't know. A custom `Port_<Name>` value can be
one port (`'8443'`), a list (`'8443,9443'`), a range (`'50000-50100'`), or use
a protocol prefix (`'udp:5060,tcp:5061'`); with no prefix it's TCP.

**If FTP is scored, write down its passive-mode data port range too.** FTP's
control port (21) is opened automatically, but passive-mode data connections
use a separate range — in IIS it's FTP Firewall Support → Data Channel Port
Range (server-level; valid ports are 1025-65535). A setting of `0-0` means
"use the Windows ephemeral range", which is 49152-65535 — write down whatever
the box actually says. Without it, a scored login can succeed while directory
listings and transfers hang. If the FTP server sits behind a firewall that does
address translation, the FTP service may also need the firewall's external IP
address (the same page has an "External IP Address of Firewall" box) or clients
will be told to connect to a private address; check with your network person. Add a pseudo-service for it, e.g.
`FTP01:FTPPassive` in `ScoredServices` and `Port_FTPPassive = '50000-50100'`
(the same range as configured in IIS). The firewall module warns if FTP is
scored and no `FTPPassive` entry exists.

- FTP passive data port range (host and range): ______________________

## Accounts to leave alone (ProtectedAccounts)

Anything you must NOT rotate the password on: shared/break-glass accounts,
anything orange team needs unchanged, and — most importantly — any
account your scoring packet uses for a functional/login-based check.
Rotating one of those breaks the check the moment you do it unless you
report the new password through whatever channel your packet requires.
If you're not sure whether an account is one of these, list it here
anyway until you've confirmed otherwise from the packet.

- ______________________
- ______________________
- ______________________

## Rule/task naming (ArtifactPrefix)

Pick a short word or two — anything that isn't an obviously
CCDC-flavored string, since the toolkit's source (including whatever the
default name would be) is sitting in a public repo. This becomes the
prefix on every firewall rule and scheduled task the toolkit creates.

- ArtifactPrefix: ______________________

## Management access (AdminSubnet)

The firewall baseline runs first now, before discovery (team decision,
2026-10-14) — so there's no "run it later once things are calmer" to fall
back on if this isn't filled in. Leaving it blank is safe (the module
defaults to 'Any', which is also the only correct answer if your ruleset
forbids source-IP restriction — check `docs/SECURITY.md` first), but
filling it in here either way avoids an interactive prompt at the exact
moment the team wants the firewall locked down with zero pauses.

- AdminSubnet (CIDR, or leave blank for 'Any'): ______________________

## Logging (Sysmon / Splunk)

- Splunk indexer address: ______________________
- Splunk indexer port (blank = default 9997): ______________________
- Splunk deployment server, if you use one (host:8089): ______________________

If you get to prep on a persistent machine beforehand (your own laptop, a
jump box you keep between sessions): download the Sysmon zip
(https://download.sysinternals.com/files/Sysmon.zip) and the Windows x64
Splunk Universal Forwarder .msi from splunk.com, and stage them in
`tools\Sysmon\` and `tools\SplunkForwarder\` respectively (both folders
are gitignored — nothing about which binaries you're carrying ends up in
the public repo either). See each module's own help
(`Get-Help .\modules\Install-Sysmon.ps1 -Full`) for exactly what it
expects to find there.

**If instead you're handed a blank box fresh at round start** (no persistent
prep machine — `git clone` is how the toolkit itself arrives, and `tools\`
is gitignored, so it does NOT come along): this only works if that box has
outbound internet. Find that out in your first few minutes of access
(`Test-NetConnection github.com -Port 443` or similar — this is also when
you find out if `git clone` itself even works). If it does:

```powershell
# Sysmon: the module does this for you.
.\modules\Install-Sysmon.ps1 -AllowDownload

# Splunk UF: the module deliberately has NO -AllowDownload (see its own
# help for why), but this exact URL was confirmed working with no account
# or EULA click-through on 2026-11-13 -- update the version number if a
# newer release has shipped by the time you need it (check
# https://www.splunk.com/en_us/download/universal-forwarder.html -> "copy
# wget link" for whatever's current):
New-Item -ItemType Directory -Path .\tools\SplunkForwarder -Force | Out-Null
Invoke-WebRequest -Uri "https://download.splunk.com/products/universalforwarder/releases/10.6.1.1/windows/splunkforwarder-10.6.1.1-b2ae2962645c-windows-x64.msi" -OutFile ".\tools\SplunkForwarder\splunkforwarder.msi" -UseBasicParsing
.\modules\Install-SplunkForwarder.ps1
```

If the box has NO internet at all, there is currently no way to get either
binary onto it — nothing in this toolkit solves that, and it needs a real
answer (NETLAB's own file-upload/transfer feature, if your environment has
one) before assuming Sysmon/Splunk will be available on game day at all.

## Network recon / packet capture (nmap / Wireshark)

Before the round: download the Windows nmap installer
(https://nmap.org/download.html) and Wireshark's Windows installer
(https://www.wireshark.org/download.html — this also gets you tshark and,
importantly, prompts to install Npcap, which capturing needs), and stage
them in `tools\nmap\` and `tools\Wireshark\` respectively (both gitignored,
same reasoning as the Sysmon/Splunk folders above). See each module's own
help (`Get-Help .\modules\Invoke-NetworkRecon.ps1 -Full` and
`Get-Help .\modules\Invoke-PacketCapture.ps1 -Full`) for exactly what's
expected where. Rehearse a `Quick`-profile nmap scan and a short tshark
capture against your practice environment ahead of time — nmap especially
needs Administrator rights and a working Npcap install to see anything
useful, better to find that out before competition day than during it.

Remember: nmap scans are loud and slow — run them pre-competition to find
your own holes, not during the round itself.

## AD hardening (if your role includes AD access)

- Will you have RSAT (ActiveDirectory + GroupPolicy modules) available on
  a domain-joined box, ideally a DC? `Invoke-ADHardening.ps1` needs both
  to do anything. ______________________
- Blue-team admin account name you intend to use (this gets added to
  Domain Admins and shared with your whole team the moment it's created —
  see docs/SECURITY.md — so agree on the name with your team ahead of
  time rather than improvising it live): ______________________
- Does your rules packet specify exact password-policy numbers (min
  length / history / lockout threshold / lockout duration)? If so, write
  them here — the module's defaults (12 / 5 / 5 / 15 min) are a
  reasonable starting point, not a requirement:
  ______________________
- GPO name to use, if you want something other than the
  `<ArtifactPrefix>-Hardening-Policy` default: ______________________
- OU to link the hardening GPO to, if not the domain root (leave blank
  for domain-wide): ______________________

## Getting the repo onto the box (rehearse this specific step)

If your environment works like a NetLab+-style remote lab, there may be
NO clipboard between your own machine and the box you're defending unless
VMware Tools (or equivalent) is installed and working — meaning you can't
copy-paste a `git clone` URL, you have to type it. Find out ahead of time
whether copy-paste works at all from your portal into the target machine,
and if it doesn't:

- Keep this repo's name and your GitHub username short and easy to type
  from memory under time pressure — write down the exact clone command you
  intend to type, not just the repo name, and rehearse typing it.
- Know the fallback too: downloading the repo as a ZIP from GitHub's web
  UI needs the same typed-URL step, so it doesn't avoid the problem, but
  confirm both paths work from inside your actual environment before day
  one, not for the first time live.
- The same typing-only constraint applies to anything a generated
  password or credential needs to go (an inject response, a teammate's
  note, etc.) — this is part of why the toolkit's random passwords avoid
  ambiguous look-alike characters (no `I`/`O`/`l`/`0`/`1`).

## Key dates — repo lock

If your event locks the public repo (freezes it, stops counting further
pushes) some time before competition day — confirm this from your rules
packet, don't assume — write that date here and treat it as the real
deadline for finishing and testing everything, not competition day itself:

- Repo lock date/time: ______________________
- Everything tested and pushed by: ______________________ (build in a
  buffer before the lock date — don't push for the first time ON the
  deadline)

## Notes / open questions

Anything you couldn't fill in ahead of time — figure these out in the
first few minutes of access, before you start running modules for real:

- ______________________
- ______________________
