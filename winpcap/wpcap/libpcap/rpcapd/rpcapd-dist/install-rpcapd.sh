#!/bin/sh

# curl -s 'http://<extrahop ip>/rpcapd/install-rpcapd.sh' | sh

# or
# curl http://<extrahop ip>/rpcapd/install-rpcapd.sh
# chmod u+x install-rpcapd.sh
# sh ./install-rpcapd.sh

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <extrahop ip> <rpcap port>" >&2
    exit 2
fi

EH_IP="$1"
RPCAP_PORT="$2"

DRYRUN=
RPCAPD_URI="http://$EH_IP/rpcapd"
RPCAPD_BIN_PATH="/usr/sbin/rpcapd"
RPCAPD_INIT_PATH="/etc/init.d/rpcapd"
RPCAPD_CFG_PATH="/etc/rpcapd.ini"
RPCAPD_BIN="rpcapd-64bit-linux"
if [ ! $(getconf LONG_BIT) = "64" ]; then
    RPCAPD_BIN="rpcapd-32bit-linux"
fi

fetch() {
    URI="$RPCAPD_URI/$1"
    echo "Fetching $2 from $URI"
    OUT="$2"
    if [ -n "$DRYRUN" ]; then
        OUT="/dev/null"
    fi
    curl "$RPCAPD_URI/$1" > "$OUT"
}

# stop rpcapd if there's already one on the system
if [ -x "$RPCAPD_INIT_PATH" ]; then
    $RPCAPD_INIT_PATH stop
fi

# download the files
fetch "$RPCAPD_BIN" "$RPCAPD_BIN_PATH"
chmod u+x "$RPCAPD_BIN_PATH"

if command -v start-stop-daemon >/dev/null 2>&1; then
    fetch "rpcapd.debianinit" "$RPCAPD_INIT_PATH"
else
    fetch "rpcapd.sysvinit" "$RPCAPD_INIT_PATH"
fi
chmod u+x "$RPCAPD_INIT_PATH"
if command -v start-stop-daemon >/dev/null 2>&1; then
    update-rc.d rpcapd defaults
else
    chkconfig --add rpcapd
fi

# write out a config file
CFG=$(cat <<EOF
ActiveClient = $EH_IP,$RPCAP_PORT
NullAuthPermit = YES
EOF
)

echo "Writing $RPCAPD_CFG_PATH with contents:"
echo "$CFG"

if [ -z "$DRYRUN" ]; then
    echo "$CFG" > "$RPCAPD_CFG_PATH"
    chmod 644 "$RPCAPD_CFG_PATH"
fi

if [ -x "$RPCAPD_INIT_PATH" ]; then
    $RPCAPD_INIT_PATH start
fi
