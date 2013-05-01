#!/bin/sh
echo ""
echo "ExtraHop Self Extracting Installer"
echo ""

cleanup()
{
    [ -d "${EXTRACTDIR}" ] && rm -rf "${EXTRACTDIR}";
}

run_installer=1;
if [ "${1}" = "-x" -o "${1}" = "--extract" ]; then
    export EXTRACTDIR="${2}"
    if [ -z "${EXTRACTDIR}" -o ! -d "${EXTRACTDIR}" ]; then
        export EXTRACTDIR=$(mktemp -d)
    fi
    run_installer=0;
    echo "Extracting files to ${EXTRACTDIR}"
else
    if [ "${#}" -lt 2 ]; then
        echo "Usage: $0 <extrahop ip> <rpcap port>" >&2
        exit 2
    fi
    export EXTRACTDIR=$(mktemp -d)
    trap cleanup EXIT
fi

ARCHIVE=$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' ${0})

tail -n+${ARCHIVE} ${0} | tar xv -C "${EXTRACTDIR}"

[ ${run_installer} -eq 0 ] && exit 0

"${EXTRACTDIR}/rpcapd.sh" -i "${EXTRACTDIR}" ${@}
exit ${?}

__ARCHIVE_BELOW__
