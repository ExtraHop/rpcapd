rpcapd Packet Forwarder
=======================

The rpcapd daemon is a thin wrapper around libpcap that allows for remote
packet capture. Clients connecting to the rpcapd server will authenticate,
choose a capture interface, optionally set up compiled BPF filters,
and start or stop the forwarding of captured packets.

rpcapd can run in two modes:

*   Passive mode - The client connects to the rpcapd server, authenticates,
    sets the capture options, and starts the capture.
*   Active mode - The rpcapd server connects to the client.  rpcapd
    does not listen for any incoming connections.

The main rpcapd source code repository is inside of the winpcap project.


Building
--------

The rpcapd source code is a few levels deep in the winpcap folder:
[winpcap/wpcap/libpcap/rpcapd/](winpcap/wpcap/libpcap/rpcapd/)

To build, first install gcc and libpcap-dev:

    sudo apt-get install build-essential libpcap-dev

Then make in the top-level folder:

    make

The resulting binary, `rpcapd`, will be in the rpcapd directory:
[winpcap/wpcap/libpcap/rpcapd/](winpcap/wpcap/libpcap/rpcapd/)

(Optional) To build the windows binary, install x86_64-w64-mingw32-gcc (or
edit vars.mk).  Running `make` will output rpcapd.exe in the rpcapd directory
in addition to the linux binary.


ExtraHop Modifications
----------------------

This repository is a modified rpcapd with some changes:

### udpstr mode

The unmodified winpcap rpcapd forwards each captured packet encapsulated
in a udp packet with some added headers:

    outer packet, with udp payload:
    struct rpcap_header
    struct rpcap_pkthdr
    full captured packet (mac addrs, ip addrs, etc)

There are a few problems with this:

*   If the captured packet was the full MTU, e.g., 1500 bytes, then rpcapd
    sends a udp packet that is 1500 bytes + rpcap headers, which is larger
    than the MTU. This results in the udp packet being sent as two
    IP fragments. Essentially, every full MTU packet capture results
    in two sent packets.

*   Each forwarded small packet increases overhead. For example, if a
    server is sending and receiving only small packets, then
    forwarding each packet in its own udp packet uses twice as
    much bandwidth as the original traffic.

*   More sent and received packets causes more overhead for the operating
    system.

udpstr mode packs multiple captured packets into full MTU-sized udp
packets:

    outer packet, with udp payload:
    struct rpcap_udpstr_header
    [ continuation of previous captured packet ]
    struct rpcap_pkthdr
    [ captured packet data ]
    struct rpcap_pkthdr
    [ captured packet data ]
    ...
    struct rpcap_pkthdr
    [ beginning captured packet data, to be continued on next udp packet ]

This results in fewer udp packets, no IP fragments, and less bandwidth
overhead. However, lost or out-of-order udp packets can mean that more than
one captured packet is lost. The struct rpcap_udpstr_header contains a sequence
number and first-header index, so only captured packets that are split across
multiple udpstr packets are lost.

### preselected interfaces

In the ExtraHop use case, rpcapd runs only in active mode, with rpcapd
connecting out to the ExtraHop system. By default,
the ExtraHop system selects the interface (e.g., eth0 or eth1) to use for capture 
by reading the IP addresses of each interface when a new rpcapd connects.
This way, all the configuration is on the ExtraHop side instead of on each
rpcapd server.

In some cases, it is best practice for the configuration to be on the server,
such as when capturing traffic from two interfaces at once. In this case, there
are added options for rpcapd to preselect the interfaces to use for capture,
regardless of how the ExtraHop system is configured.

