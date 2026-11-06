# Copy this file to answers.local.psd1 (same folder) and fill in what you
# know ahead of time from your printed prep sheet (see docs/PREP-SHEET.md).
#
# answers.local.psd1 is gitignored — it will NEVER get committed or pushed
# to the public repo. This file (the template) is the only one that's
# public, and it has no real values in it on purpose.
#
# Anything you leave blank or out entirely just means the toolkit will
# prompt you for it interactively instead. Nothing here is required.

@{
    # Used by Get-EnvironmentInventory.ps1 when there's no AD to query.
    # CIDR form, e.g. "10.10.10.0/24"
    SubnetCidr      = ''

    # Used by Get-EnvironmentInventory.ps1. Comma-separated, "HOST:Service"
    # pairs (or bare "Service" if it applies to every host), straight from
    # your team's scoring packet. Example:
    # 'DC01:DNS,DC01:LDAP,WEB01:HTTP,WEB01:HTTPS,MAIL01:SMTP'
    ScoredServices  = ''

    # Used by Invoke-FirewallBaseline.ps1. Your team's admin/management
    # subnet — NOT "any" — so RDP/WinRM stay open only to your own people.
    AdminSubnet     = ''

    # Add one Port_<ServiceName> entry per custom/unmapped service name you
    # expect to see in ScoredServices that isn't a standard one the
    # toolkit already knows (DNS, LDAP, HTTP, HTTPS, SMB, RDP, WinRM, FTP,
    # SSH, SMTP, POP3, IMAP, MSSQL, DHCP, NTP, Kerberos). The value can be a
    # single port, a list, a range, or carry a protocol prefix (TCP if none):
    # Port_CustomApp = '8443'
    # Port_CustomApp = '8443,9443'
    # Port_Voice     = 'udp:5060,tcp:5061'
    #
    # If FTP is scored, its passive-mode DATA ports are a separate range
    # from control port 21 (IIS: FTP Firewall Support -> Data Channel Port
    # Range). List a pseudo-service for it in ScoredServices
    # (e.g. 'FTP01:FTPPassive') and give the same range here:
    # Port_FTPPassive = '50000-50100'

    # Used by Invoke-CredentialHardening.ps1, and by Invoke-ADHardening.ps1's
    # stale-account audit (accounts listed here are never flagged/disabled
    # even if they look stale). Comma-separated account names that must
    # NEVER get an automatic password reset — anything your scoring packet
    # ties to a functional/login check. See docs/SECURITY.md for why this
    # matters (rotating one of these breaks the check immediately unless
    # you report the new password through whatever channel your packet
    # requires).
    ProtectedAccounts = ''

    # Used by Invoke-FirewallBaseline.ps1 and Invoke-ADHardening.ps1
    # (its hardening GPO defaults to "<ArtifactPrefix>-Hardening-Policy").
    # Prefix for the firewall rule, scheduled-task, and GPO names it
    # creates. Pick anything that isn't an obvious "CCDC" string — see
    # docs/SECURITY.md's fingerprinting note. Falls back to a generic
    # default if left blank.
    ArtifactPrefix  = ''

    # Used by Install-SplunkForwarder.ps1. Your Splunk indexer's
    # hostname/IP — required, there's no sensible default for this.
    SplunkIndexerAddress = ''

    # Used by Install-SplunkForwarder.ps1. Your Splunk deployment server,
    # host:mgmt-port (default mgmt port is 8089). Leave blank to skip —
    # not every environment uses one.
    SplunkDeploymentServer = ''

    # Used by Invoke-AdminConsole.ps1's AD actions and Invoke-ADHardening.ps1's
    # blue-team admin account. Your domain name (e.g. "domain.local"), for
    # building new users' UPNs and as the default DNS zone. Leave blank to
    # skip UPN assignment / be prompted per action.
    DomainName      = ''

    # Used by Invoke-AdminConsole.ps1's "create AD user" action. OU
    # distinguished name new users land in by default (e.g.
    # "OU=Users,DC=domain,DC=local"). Leave blank to use AD's own default
    # location.
    DefaultOU       = ''
}
