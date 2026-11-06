# DNS Field Guide -- for the person who has to own it

You said you know a good bit about AD but haven't spent a full day actually
working it, and you know less about DNS. That's a completely normal place
to start from, and it's fixable before competition day. This guide is not
a general DNS tutorial -- the internet has plenty of those and most of it
doesn't apply here. This is specifically: what DNS is doing in *this*
environment, what breaks it, what a red team does to it, and how to tell
what's wrong fast enough to matter in a round.

Read the explanation sections once, slowly, with the lab DC in front of
you if you can. Then do the exercises for real -- reading about DNS and
having actually broken and fixed it are very different levels of
"knowing DNS," and only one of them survives contact with a live round.

---

## 1. Why this is worth your time specifically

Three facts, from your own packet and your own team's history, that make
this not optional:

- **DNS is a scored service.** It's in the same scoring bucket as HTTP,
  HTTPS, SMTP and POP3. A DNS outage isn't background noise -- it's points,
  the same as any other service going down.
- **Nothing else on the Windows side works without it.** Active Directory
  on your DC is *AD-integrated DNS* -- not a separate service that happens
  to sit next to AD, but DNS data stored inside AD itself (more on this in
  section 2). Every login, every Group Policy pull, every "where's the
  domain controller" lookup starts with a DNS query. If DNS is wrong, AD
  *looks* broken even when every AD setting is perfect.
- **This already happened to your team.** The intel from last year was
  specific: AD went down because a file DNS depends on got renamed with an
  added space. Nobody on the team recognized it fast, because trailing
  whitespace in a filename is invisible to the eye and Windows silently
  treats `file.dns ` as a completely different file from `file.dns`. That
  is a DNS-shaped failure wearing an "AD is down" costume, and you are the
  person whose job it is to recognize that costume on sight.

`Invoke-ConfigBaseline.ps1` fingerprints zone *files* by hash, which
matters for a **file-backed** zone -- but `lab.local` is AD-integrated
(section 2 explains the difference), and an AD-integrated zone has no
single flat file to hash the same way. On the real lab DC that check
currently finds zero files to track for exactly this reason. That's not
necessarily wrong, but it means "the toolkit already catches a repeat of
the renamed-file incident" is not something to assume true without
checking what the real mechanism was -- see Exercise 3.

---

## 2. The one idea that makes everything else make sense

**On your domain controller, DNS zone data is stored inside Active
Directory, not in a plain file the DNS service owns by itself.** This is
called an **AD-integrated zone**, and it's the default for a zone hosted
on a domain controller, and it's what `lab.local` is in your practice lab.

What that buys you:
- The zone replicates automatically between domain controllers, the same
  way user accounts and group memberships do.
- Clients can add their own DNS records automatically (**dynamic
  updates** -- see section 4) once they've authenticated to the domain,
  instead of someone manually typing in every machine's A record.

What that costs you:
- DNS and AD are now genuinely one system wearing two hats. A problem
  that looks like "DNS is broken" can really be an AD replication problem,
  and a problem that looks like "nobody can log in" can really be DNS
  handing out wrong answers. You cannot treat them as two unrelated
  things to check separately.
- **There is no single flat zone file to point at.** The actual records
  live inside AD itself, in two special partitions created when AD is
  installed: `ForestDnsZones` and `DomainDnsZones`. A traditional
  file-backed zone writes a `<zonename>.dns` file under
  `%windir%\System32\Dns`; an AD-integrated zone doesn't, by default. This
  matters: it means "find the DNS file and see if it got renamed" isn't
  as simple a move here as it sounds, and it's exactly why Exercise 3
  below is something to actually go look at together rather than assume.

### How domain controllers find each other (SRV records)

This is the part most people never think about until it breaks, and it's
the part that actually explains the "renamed file" incident.

A domain controller doesn't just get *looked up* by name -- it
**advertises itself** into DNS the moment it starts up healthy, via a
special set of records called **SRV records**, under a subdomain called
`_msdcs.<yourdomain>`. Open the DNS tab in the toolkit window, look at the
`_msdcs.lab.local` zone, and you'll see entries like:

```
_ldap._tcp.dc._msdcs.lab.local       SRV   -> LABDC.lab.local
_kerberos._tcp.dc._msdcs.lab.local   SRV   -> LABDC.lab.local
```

Read that as: *"if you want to talk LDAP to a domain controller, or get a
Kerberos ticket, here is which machine to go ask."* Every single
domain-joined machine reads these records before it can log a user in,
pull a Group Policy, or do almost anything domain-related. **No SRV
records means no logins, even though the domain controller itself is
running perfectly.** That is exactly what a renamed/corrupted DNS zone
file does -- the records those SRV entries live in stop being readable,
the advertisement disappears, and every client in the domain starts
failing to find a DC it is sitting right next to.

This is also why "just restart the DC" sometimes looks like it fixes
things and sometimes does nothing: if the underlying zone data is intact
and it's a service hiccup, a restart re-registers everything and it comes
back. If the zone *file itself* is gone or renamed, a restart changes
nothing, because there's nothing to re-register from.

### The records worth recognizing on sight

| Type | What it answers | Why you'd care here |
|---|---|---|
| **A** | "What's the IP for this hostname?" | Every domain-joined machine has one. The bread and butter record. |
| **SRV** | "Which machine provides this *service*?" | How clients find a DC at all -- see above. |
| **CNAME** | "This name is really just an alias for that other name." | A red team repointing a legitimate-looking name at their own box is a classic hijack. |
| **TXT** | Arbitrary text attached to a name. | Legitimate uses exist, but it's also the easiest record type to smuggle data through (exfiltration/tunneling). This is why the toolkit's DNS audit flags every TXT record for a human to read. |
| **PTR** | The reverse of an A record: "whose IP is this?" | Lives in a *reverse lookup zone*, separate from your normal zone. Easy to forget exists. |

You do not need to memorize the rest of the DNS record zoo (MX, NS, SOA,
etc.) to do this job well. These five cover essentially everything you'll
touch in this environment.

---

## 3. Telling DNS-broken apart from AD-broken apart from network-broken

This is the actual skill. Here's the fast version, in order, each step
assuming the one before it passed:

1. **Is the box even reachable?** `Test-Connection <dc-hostname>`. If this
   fails, you have a network/firewall problem, not a DNS problem -- stop
   here and look at the firewall, not the DNS zone.
2. **Does DNS answer at all?** `Resolve-DnsName -Name <anything you know
   should exist> -Server <dc-ip>`. Point `-Server` straight at the DC's IP
   so you're testing the DNS *service*, not whatever DNS server your own
   machine happens to be configured to use. A timeout or "server failed to
   respond" here means the DNS *service* is down or unreachable, which you
   can confirm with `Get-Service DNS` on the DC itself.
3. **Does it answer with the RIGHT thing?** If step 2 got an answer but
   logins still fail, check the SRV records specifically:
   `Resolve-DnsName -Name _ldap._tcp.dc._msdcs.<domain> -Type SRV -Server
   <dc-ip>`. No result, or a result pointing at the wrong machine, means
   the zone data itself is wrong, missing, or (per the real incident) the
   underlying file it's supposed to be reading got tampered with.
4. **If the zone data looks wrong, check what actually changed.** This is
   what `Invoke-ConfigBaseline.ps1 -Action Verify` and the Window's
   Dashboard are for -- they tell you specifically whether a zone's file
   hash, its transfer setting, or its dynamic-update setting changed since
   your last known-good baseline, instead of you guessing.
5. **If AD itself looks unreachable** (can't query `Get-ADUser`, etc.)
   *after* DNS has confirmed healthy, now you're looking at an actual AD
   problem -- replication, the NTDS service, disk space on the DC -- not a
   DNS one.

Notice the order: **network, then DNS, then AD.** Checking them in the
wrong order is how a DNS problem gets forty-five minutes of someone
staring at AD settings that were never wrong.

---

## 4. The three things your tooling actually checks, and why

You already have `Invoke-DnsHardening.ps1` and the DNS tab in the toolkit
window. Here's what each check is really asking, so the tool's output
means something to you instead of being "red bad, green good."

- **Zone transfers.** A zone transfer is a DNS server handing its *entire
  zone* -- every record it knows about -- to whoever asks, in one request.
  It exists so a secondary DNS server can legitimately copy a primary's
  data. The problem: if it's set to "any server," it also hands that same
  complete map of every hostname and address in your domain to an
  attacker who just asks for it, no credentials required. That's why
  `-SecureZoneTransfers` sets it to `NoTransfer` -- nobody gets a copy
  unless you've explicitly listed them.
- **Dynamic updates.** This controls whether a machine can add/update its
  *own* DNS record automatically, the way domain-joined machines normally
  do. "Nonsecure" means **any** device on the network can add or
  overwrite a record with no authentication at all -- including adding a
  fake record for a name that doesn't belong to it. "Secure" means only
  an authenticated domain member can update its own record. This is a
  direct answer to "how would someone sneak a malicious record in" -- on a
  nonsecure zone, they'd just ask for one.
- **Cache locking / pollution protection.** Your DNS server caches
  answers it looks up on your behalf (for external names, if it does any
  recursive resolution at all). Cache locking stops a cached entry from
  being overwritten before its TTL expires; pollution protection refuses
  to cache unrelated records that rode along in a response you didn't ask
  for. Both exist to stop someone from poisoning what your own server
  believes, which is a much quieter attack than anything touching your
  zone directly.

One switch is deliberately **not** bundled with the other three:
`-DisableRecursion`. Recursion is what lets your DNS server look up names
*outside* your domain on a client's behalf. If anything in this
environment needs to resolve an external name through this server,
turning recursion off breaks that lookup immediately -- and DNS is scored,
so that's a self-inflicted outage. Only flip it if you've confirmed
nothing here depends on it.

---

## 5. What a red team actually does to DNS (and how you'd catch it)

Concrete, not theoretical -- this is the shape of what you're watching for:

| They do this | It looks like | You catch it with |
|---|---|---|
| Rename/corrupt a DNS dependency | AD "mysteriously" stops letting anyone log in, DC looks fine | Untested on an AD-integrated zone right now -- see Exercise 3. `Invoke-ConfigBaseline.ps1`'s zone-file hash only covers a file-backed zone. |
| Add a malicious A/CNAME record | A legitimate-looking hostname quietly resolves somewhere it shouldn't | The DNS tab's record grid + the "worth a look" flags (wildcard, off-subnet, short TTL) |
| Pull a full zone transfer | Nothing visible changes at all -- they just now have your whole network map | Zone transfer is already set to refuse this if you've run the hardening |
| Add a record via nonsecure dynamic update | A new record appears with no corresponding new domain-joined machine | Dynamic updates set to Secure; the threat hunt flags new DNS records since the last pass |
| Stop or crash the DNS service | Everything downstream fails at once -- logins, web, mail, all of it | `Get-Service DNS` is the first thing to check, and it's cheap enough to check constantly |

The pattern worth internalizing: **most of these are quiet on purpose.**
A full outage gets noticed in minutes. A single malicious record added to
a zone of hundreds doesn't, unless something is specifically watching for
*new since last time* -- which is exactly what the threat hunt and the
config baseline are for. Read-only, cheap, and the only thing standing
between "nobody noticed for six hours" and "caught it in one pass."

---

## 6. Do these for real, in the lab, before competition day

Reading the sections above gets you vocabulary. These exercises get you
the actual skill. All of them are safe -- they're against your own
practice lab, every change is backed up first, and the lab has a
`clean-baseline` checkpoint if anything needs a hard reset.

**Exercise 1 -- look at what's actually there.**
Open the toolkit window on `CcdcLab-DC`, go to the DNS tab, click
**List zones**, then select `lab.local` and click **List records in
selected zone**. For every record type you don't immediately recognize,
find it in the table in section 2. Do the same for `_msdcs.lab.local` and
find the SRV records from section 2 for real.

**Exercise 2 -- watch the lookup actually happen.**
From a different VM (`CcdcLab-WEB` is fine), run:
```powershell
Resolve-DnsName -Name labdc.lab.local -Server <the DC's IP>
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.lab.local -Type SRV -Server <the DC's IP>
```
Watch what comes back, and match it against what you saw in the DNS tab's
grid. This is the step that makes "a client looks up an SRV record" stop
being an abstract sentence and start being something you've watched
happen.

**Exercise 3 -- go find the real mechanism behind the incident that
already happened to this team, together.**
This is the single most valuable thing you can do before competition
day, and I'm deliberately not writing it as a fixed set of steps, because
I don't actually know yet what the renamed file in the real incident
really was -- and neither do you, which is the point. `lab.local` is
AD-integrated (section 2), so there's no single obvious `.dns` file to
point at the way there would be on a file-backed zone. Something clearly
got renamed; finding out exactly what, on a real DC, is the exercise.

Say the word and we'll do this live against `CcdcLab-DC`: look at what
Windows DNS Server actually keeps on disk even for an AD-integrated zone
(there are a few candidates -- cache/root-hint files, service-start
dependencies, the zone's registry entries), reason through which of
those, if renamed, would produce "AD looks down but the DC is fine,"
reproduce it safely against the lab, and watch it fail and recover. That
process -- investigate, don't assume -- is worth more than any specific
file path I could hand you, because it's the same process you'd need
mid-round if the real thing happens again and looks even slightly
different the second time.

**Exercise 4 -- make a change and verify it.**
In the DNS tab, add an A record to `lab.local` (something obviously a
test, like `exercise-a`). Confirm it with `Resolve-DnsName` from another
VM. Then remove it from the tab and confirm the lookup fails again. This
is the muscle memory for the most common inject shape: "add this record"
or "this record shouldn't be there, get rid of it."

**Exercise 5 -- run the hardening toggles and read what changed.**
Run the DNS audit (Modules tab) against `CcdcLab-DC` first and read every
line of output -- don't skim it. Then use the DNS tab's **Secure
transfers** and **Secure dynamic updates** buttons on `lab.local`, and
run the audit again. Compare the two reports. This is where sections 2
and 4 stop being reading and start being something you've seen move from
red to green yourself.

---

## 7. Quick reference (print this part)

**Diagnose, in order:** reachable? -> DNS answers? -> DNS answers
*correctly* (check SRV)? -> what changed (baseline verify)? -> only then
suspect AD itself.

```powershell
# Is the DC reachable at all
Test-Connection <dc-ip-or-hostname>

# Does DNS answer, asked directly (not through your own resolver)
Resolve-DnsName -Name <known-good-hostname> -Server <dc-ip>

# Can clients find a domain controller (the SRV check)
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.<domain> -Type SRV -Server <dc-ip>

# Is the service itself even running
Get-Service DNS -ComputerName <dc-hostname>

# What changed since the last known-good state
.\modules\Invoke-ConfigBaseline.ps1 -Action Verify
```

**In the toolkit window, DNS tab:**
- Red "Any server" under Zone transfers = refuses nothing, fix with
  **Secure transfers**.
- Anything other than `Secure` under Dynamic updates on an AD-integrated
  zone = fix with **Secure dynamic updates**.
- A record in the grid with something in its "Worth a look" column isn't
  automatically malicious -- read it and decide, same as the module says.

**The one failure mode to never forget:** something DNS depends on being
renamed or corrupted causes an AD-shaped outage with a DC that looks
perfectly healthy. If logins are failing and the DC itself seems fine,
check DNS before you check anything else in AD -- regardless of whether
the exact mechanism turns out to be a zone file, a different on-disk
dependency, or something else Exercise 3 turns up.
