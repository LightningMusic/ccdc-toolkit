#!/usr/bin/env bash
# Changes a Palo Alto (PAN-OS) administrator's password over SSH -- bash
# equivalent of Set-FirewallPassword.ps1, for a teammate on Linux. Same
# logic, same safety checks, just native ssh instead of Windows' ssh.exe.
#
# Built the day before the Invitational, after red team was found running
# an SSH script against default credentials (router and firewall both).
#
# PAN-OS stores one credential shared by the CLI and the web admin UI --
# changing it here changes both (confirmed directly on this team's own
# device, not assumed).
#
# The username is NEVER changed -- competition rules forbid that; only the
# password does.
#
# LOWER CONFIDENCE THAN set-router-password.sh, SAY SO PLAINLY: PAN-OS's
# password prompt is a masked, character-level read, not a simple
# line-buffered one like VyOS's. Piping the new password to it over SSH
# SHOULD work the same way (this is a documented, commonly used PAN-OS
# automation pattern), but this has not been live-tested against a real
# PAN-OS device as of writing this -- test it once, deliberately, before
# relying on it under pressure. If it does anything other than cleanly
# confirm success, STOP and use the Web UI fallback instead (Device >
# Administrators > click the account > enter the new password > OK >
# Commit) rather than retrying blind against a firewall.
#
# Refuses a password containing ' " $ ` or ! for the same reason as the
# router script: PAN-OS's underlying shell is bash-derived (the same
# history-expansion risk for !), and the other three would break this
# script's own command construction. Every other symbol is fine.
#
# Usage:
#   ./set-firewall-password.sh -h <firewall-ip> [-u <username>] [-g]
#     -h   Firewall management IP/hostname (required)
#     -u   PAN-OS administrator account to change (default: admin)
#     -g   Generate a strong password instead of prompting for one
#
# Example:
#   ./set-firewall-password.sh -h 172.16.0.1

set -euo pipefail

HOST=""
USERNAME="admin"
GENERATE=0

while getopts "h:u:g" opt; do
    case "$opt" in
        h) HOST="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        g) GENERATE=1 ;;
        *) echo "Usage: $0 -h <firewall-ip> [-u <username>] [-g]" >&2; exit 1 ;;
    esac
done

if [ -z "$HOST" ]; then
    echo "ERROR: -h <firewall-ip> is required." >&2
    echo "Usage: $0 -h <firewall-ip> [-u <username>] [-g]" >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: ssh not found on PATH. Install openssh-client (apt: sudo apt install openssh-client)." >&2
    exit 1
fi

echo "WARNING: changing the PAN-OS password for '$USERNAME' on $HOST. This does NOT touch the username -- only passwords may change mid-competition. This script is lower-confidence than the router one -- see its own header comment -- watch the output closely."

generate_clean_password() {
    local chars='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789@#%^&*-_+'
    local pw=""
    local i
    for i in $(seq 1 20); do
        pw="${pw}${chars:$((RANDOM % ${#chars})):1}"
    done
    echo "$pw"
}

PLAIN_PASSWORD=""
if [ "$GENERATE" -eq 1 ]; then
    PLAIN_PASSWORD="$(generate_clean_password)"
    echo "WARNING: generated password for '$USERNAME': $PLAIN_PASSWORD -- write this down now. It will not be shown again."
else
    read -r -s -p "New password for '$USERNAME' on $HOST: " FIRST
    echo
    read -r -s -p "Type it again to confirm: " CONFIRM
    echo
    if [ "$FIRST" != "$CONFIRM" ]; then
        echo "ERROR: those two entries didn't match. Nothing was changed -- run this again." >&2
        exit 1
    fi
    PLAIN_PASSWORD="$FIRST"
fi

if [ -z "$PLAIN_PASSWORD" ]; then
    echo "ERROR: no password to apply. Nothing changed." >&2
    exit 1
fi

for bad_char in "'" '"' '$' '`' '!'; do
    if [[ "$PLAIN_PASSWORD" == *"$bad_char"* ]]; then
        echo "ERROR: that password contains a character this script can't safely carry through to PAN-OS's shell ($bad_char). Avoid: ' \" \$ \` ! -- every other symbol is fine. Pick a different password, or use -g. Nothing was changed." >&2
        exit 1
    fi
done

echo "Connecting to $HOST over SSH as '$USERNAME'..."
# StrictHostKeyChecking=no: see set-router-password.sh's identical note --
# a first-contact management connection with no known_hosts entry would
# otherwise hang on an unanswerable interactive prompt.
#
# 'set mgt-config users <name> password' itself prompts twice more (new,
# then confirm) -- those are the next two lines fed over stdin, not part
# of the command text itself.
if ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$USERNAME@$HOST" <<EOF
configure
set mgt-config users $USERNAME password
$PLAIN_PASSWORD
$PLAIN_PASSWORD
commit
exit
EOF
then
    echo "OK: commands sent and ssh exited cleanly. VERIFY by logging into the Web UI with the new password before walking away -- scroll back through the output above first; if 'commit' doesn't show success there, the change did not take even though ssh itself exited cleanly."
else
    echo "ERROR: use the Web UI fallback instead: Device > Administrators > click '$USERNAME' > enter the new password > OK > Commit (top right). Don't retry this script blind against a firewall." >&2
    exit 1
fi
