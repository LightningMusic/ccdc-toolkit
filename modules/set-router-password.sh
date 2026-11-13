#!/usr/bin/env bash
# Changes the VyOS router's login password over SSH -- bash equivalent of
# Set-RouterPassword.ps1, for a teammate on Linux. Same logic, same safety
# checks, just native ssh instead of Windows' ssh.exe.
#
# Built the day before the Invitational, after red team was found running
# an SSH script against the router's default credentials.
#
# The username is NEVER changed -- competition rules forbid that; only the
# password does.
#
# Refuses a password containing ' " $ ` or ! -- VyOS's shell is
# bash-derived and a bare ! in a piped command can trigger bash history
# expansion ("event not found") instead of landing in the password
# literally, and the other four would break either this script's own
# command construction or the single-quoting it wraps the password in on
# the remote side. Every other symbol is fine.
#
# Not live-tested against a real VyOS device as of writing this -- piping
# commands to an interactive-mode CLI over ssh -tt is a well-established
# pattern, but test this against your actual router BEFORE trusting it
# under pressure, and have a console/physical-access fallback ready in
# case it doesn't behave the way this expects on your specific build.
#
# Usage:
#   ./set-router-password.sh -h <router-ip> [-u <username>] [-g]
#     -h   Router management IP/hostname (required)
#     -u   VyOS login account to change (default: vyos)
#     -g   Generate a strong password instead of prompting for one
#
# Example:
#   ./set-router-password.sh -h 172.16.0.2
#   ./set-router-password.sh -h 172.16.0.2 -g

set -euo pipefail

HOST=""
USERNAME="vyos"
GENERATE=0

while getopts "h:u:g" opt; do
    case "$opt" in
        h) HOST="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        g) GENERATE=1 ;;
        *) echo "Usage: $0 -h <router-ip> [-u <username>] [-g]" >&2; exit 1 ;;
    esac
done

if [ -z "$HOST" ]; then
    echo "ERROR: -h <router-ip> is required." >&2
    echo "Usage: $0 -h <router-ip> [-u <username>] [-g]" >&2
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    echo "ERROR: ssh not found on PATH. Install openssh-client (apt: sudo apt install openssh-client)." >&2
    exit 1
fi

echo "WARNING: changing the VyOS login password for '$USERNAME' on $HOST. This does NOT touch the username -- only passwords may change mid-competition."

generate_clean_password() {
    # Upper/lower/digit plus a few safe symbols -- deliberately excludes
    # ' " $ ` ! (see header comment for why), and the look-alike l/1/O/0
    # pair that's hard to read off a screen under time pressure.
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
        echo "ERROR: that password contains a character this script can't safely carry through to VyOS's shell ($bad_char). Avoid: ' \" \$ \` ! -- every other symbol is fine. Pick a different password, or use -g. Nothing was changed." >&2
        exit 1
    fi
done

echo "Connecting to $HOST over SSH as '$USERNAME'..."
# StrictHostKeyChecking=no: this is a first-contact management connection
# with no prior known_hosts entry on most machines that would run this --
# the interactive "are you sure (yes/no)" prompt ssh would otherwise print
# cannot be answered once stdin is already feeding it the config commands
# below; it would just hang. Accepted deliberately for this internal
# management link, not a general recommendation.
if ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$USERNAME@$HOST" <<EOF
configure
set system login user $USERNAME authentication plaintext-password '$PLAIN_PASSWORD'
commit
save
exit
EOF
then
    echo "OK: password-change commands sent and ssh exited cleanly. VERIFY by logging in with the new password before walking away -- a config that looked like it went through but didn't commit/save is the worst version of this to find out about later."
else
    echo "ERROR: ssh exited with a non-zero status -- the commands above may not all have applied. Log in manually (console if SSH itself is now in doubt) and check: show configuration commands | match login" >&2
    exit 1
fi
