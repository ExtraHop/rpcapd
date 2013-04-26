#!/bin/sh

# curl --fail -k 'https://<extrahop_ip>/rpcapd/install-rpcapd.sh' > install-rpcapd.sh && sudo sh ./install-rpcapd.sh <extrahop_ip> <rpcap_port_from_running_config>

RPCAPD_BIN_PATH="/usr/sbin/rpcapd"
RPCAPD_INIT_PATH="/etc/init.d/rpcapd"
RPCAPD_CFG_PATH="/etc/rpcapd.ini"

usage() {
    cat 2<&1 <<EOM
Usage: $0 <extrahop_ip> <rpcap_port>

To install from files in the current directory:

    $0 -i ./ <extrahop_ip> <rpcap_port>

To only fetch files into the current directory but not install them:
  (The script can be run again with -i ./ to actually install)

    $0 -o ./ <extrahop_ip> <rpcap_port>


Options:
  -u 'https://foobar/rpcapd/': fetch files from https://foobar/rpcapd/ instead
                               of https://<extrahop_ip>/rpcapd/.
  -i <directory>: Use install files from directory, instead of fetching
                  from <extrahop_ip>.
  -o <directory>: Only output fetched files to <directory>, and don't install.
                  After running -o <directory>, run with -i <directory> to
                  actually install rpcapd.
  -c: Only update the configuration file, $RPCAPD_CFG_PATH,
      with <extrahop_ip> and <rpcap_port>
  -h: Print help.
EOM
    exit 2
}

# ============================ Parse Arguments ================================

fetch_uri=
fetch_dir=
no_fetch=
fetch_only=
cfg_update_only=

# process arguments
OPTIND=1
while getopts "u:i:o:ch" opt; do
    case "$opt" in
        u) fetch_uri="$OPTARG";;
        i) fetch_dir="$OPTARG"; no_fetch="y";;
        o) fetch_dir="$OPTARG"; fetch_only="y";;
        c) cfg_update_only="y";;
        h) usage;;
    esac
done
shift $((OPTIND-1))

# positional arguments: <extrahop_ip> <rpcap_port>
[ "$#" -lt 2 ] && usage
eh_ip="$1"
rpcap_port="$2"
shift 2

# any following arguments get passed to rpcapd
[ "$1" = "--" ] && shift
rpcapd_extra_args="$@"

# ========================= Detect Platform ===================================

arch="$(uname -m)"
rpcapd_bin="rpcapd-64bit-linux"
if [ "$arch" = "x86_64" ]; then
    : # default
elif [ "$arch" = "i386" -o "$arch" = "i486" -o "$arch" = "i586" -o \
       "$arch" = "i686" ]; then
    rpcapd_bin="rpcapd-32bit-linux"
else
    echo "Warning: unrecognized platform $arch, defaulting to $rpcapd_bin"
fi

rpcapd_init="rpcapd.debianinit"
init_add_cmd="update-rc.d rpcapd defaults"
if command -v start-stop-daemon >/dev/null 2>&1; then
    : # default
elif command -v chkconfig >/dev/null 2>&1; then
    rpcapd_init="rpcapd.sysvinit"
    init_add_cmd="chkconfig --add rpcapd"
else
    echo "Warning: unrecognized init system,"
    echo "         defaulting to $rpcapd_init, $init_add_cmd"
fi

# ========================= Fetch Binary / init script ========================

fetch() {
    uri="$fetch_uri/$1"
    out="$2"
    echo "Fetching $uri > $out"
    if ! curl --fail -k "$uri" > "$out"; then
        echo "Error: Fetching $uri > $out failed!"
        exit 1
    fi
}

ensure_exists() {
    if [ ! -f "$1" ]; then
        echo "Error: Missing file $1"
        exit 1
    fi
}

[ -z "$fetch_uri" ] && fetch_uri="https://$eh_ip/rpcapd"

if [ -n "$fetch_only" ]; then
    RPCAPD_BIN_PATH="$fetch_dir/$rpcapd_bin"
    RPCAPD_INIT_PATH="$fetch_dir/$rpcapd_init"
    RPCAPD_CFG_PATH="$fetch_dir/rpcapd.ini"
elif [ -x "$RPCAPD_INIT_PATH" ]; then
    echo "Stopping $RPCAPD_INIT_PATH"
    $RPCAPD_INIT_PATH stop
fi
if [ -z "$cfg_update_only" ]; then
    if [ -n "$no_fetch" ]; then
        ensure_exists "$fetch_dir/$rpcapd_bin"
        ensure_exists "$fetch_dir/$rpcapd_init"
        set -e
        cp -f "$fetch_dir/$rpcapd_bin" "$RPCAPD_BIN_PATH"
        cp -f "$fetch_dir/$rpcapd_init" "$RPCAPD_INIT_PATH"
        set +e
    else
        fetch "$rpcapd_bin" "$RPCAPD_BIN_PATH"
        fetch "$rpcapd_init" "$RPCAPD_INIT_PATH"
    fi
    set -e
    chmod u+x "$RPCAPD_BIN_PATH"
    chmod u+x "$RPCAPD_INIT_PATH"
    set +e
fi

if [ -n "$rpcapd_extra_args" ]; then
    # update DAEMON_ARGS="..." in the init file
    echo "Adding extra DAEMON_ARGS=\"... $rpcapd_extra_args\""
    set -e
    sed -i "s|^\(DAEMON_ARGS=\".*\)\"$|\1 $rpcapd_extra_args\"|" \
           "$RPCAPD_INIT_PATH"
    set +e
fi

cfg=$(cat <<EOF
ActiveClient = $eh_ip,$rpcap_port
NullAuthPermit = YES
EOF
)

echo "Writing config to $RPCAPD_CFG_PATH with contents:"
echo "$cfg"

set -e
echo "$cfg" > "$RPCAPD_CFG_PATH"
chmod 644 "$RPCAPD_CFG_PATH"
set +e

if [ -z "$fetch_only" -a -x "$RPCAPD_INIT_PATH" ]; then
    echo "Adding $RPCAPD_INIT_PATH to startup via $init_add_cmd"
    $init_add_cmd
    echo "Starting $RPCAPD_INIT_PATH"
    $RPCAPD_INIT_PATH start
fi

