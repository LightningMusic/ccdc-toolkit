# Bundled Sysmon config

`sysmonconfig-export.xml` in this folder is vendored **unmodified** from
[SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
(source version 74, 2021-07-08). It's released under Creative Commons
Attribution 4.0 — the license text is right in the file's own header
comment, which explicitly permits "privatize, fork, edit, teach, publish,
or deploy for commercial use — with attribution in the text." That header
is kept intact in this copy on purpose; don't strip it if you edit this
file, and if you fork/modify it, fill in the "Fork version / Fork author /
Fork project / Fork license" fields the header already has placeholders
for — that's the attribution the license asks for.

It's a solid, widely-used default — not the only option. Olaf Hartong's
[sysmon-modular](https://github.com/olafhartong/sysmon-modular) is more
exhaustive and worth a look once you know more about what your specific
environment needs to catch (see `docs/ARCHITECTURE.md`'s roadmap notes).

## Using a different config

Pass `-ConfigPath` to `modules/Install-Sysmon.ps1`, or drop a replacement
file in this folder and update the default path — either way, nothing in
`Install-Sysmon.ps1` assumes this exact file, it just needs *some* valid
Sysmon config XML to point at.
