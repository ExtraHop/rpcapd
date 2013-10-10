rpcapd Packet Forwarder
=======================

The rpcapd server is a thin wrapper around libpcap that forwards captured
packets to connected clients.  The usual use case is to run rpcapd on a server,
for example an AWS instance, and then connect to the instance with Wireshark
to capture all the packets the instance sees. rpcapd supports most libpcap
features, for example using bpf filters to reduce network load by only
forwarding packets that you're interested in.

The main rpcapd source code repository is inside of the winpcap project.


Development
-----------

The rpcapd source code is a few levels deep in the winpcap folder:

    [winpcap/wpcap/libpcap/rpcapd/](winpcap/wpcap/libpcap/rpcapd/)

To build, first install gcc and libpcap-dev:

    sudo apt-get install build-essential libpcap-dev

Then make in the top-level folder:

    make

The resulting binary will be in the rpcapd directory:

    winpcap/wpcap/libpcap/rpcapd/

(Optional) To build the windows binary, install x86_64-w64-mingw32-gcc (or
edit vars.mk).  Running `make` will output rpcapd.exe in the rpcapd directory
in addition to the linux binary.


ExtraHop Modifications
----------------------

This repository is a modified rpcapd with some changes:

### udpstr mode

The vanilla rpcapd forwards each captured packet encapsulated
in a udp packet with some added headers:

    outer packet, with udp payload:
    struct rpcap_header
    struct rpcap_pkthdr
    full captured packet (mac addrs, ip addrs, etc)

There are a few problems with this:

a.  If the captured packet was the full MTU, e.g. 1500 bytes, then rpcapd
    will send a udp packet that's 1500 bytes + rpcap headers, so larger
    than MTU.  This results in the udp packet getting sent as two
    IP fragments.  Essentially every full MTU packet captured results
    in two sent packets.

b.  Each forwarded small packet will have a lot of overhead.  Suppose a
    server was only sending and receiving small packets, then
    forwarding each packet in its own udp packet would be twice as
    much bandwidth as the original traffic.

c.  More sent/received packets causes more overhead for the operating system.

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
overhead.  It's a little less resilient to lost or out of order udp packets,
but there are is a sequence number and first-header index in the
struct rpcap_udpstr_header, so only captured packets that are split across
udpstr packets are lost.

### preselected interfaces

In the ExtraHop use case, rpcapd only runs in active mode, with rpcapd
connecting out to the ExtraHop instead of the other way around.  By default,
the ExtraHop will select which interface to capture on, e.g. eth0 vs eth1,
by looking at the IP addresses of each interface when a new rpcapd connects.
This way, all the configuration is on the ExtraHop side instead of on each
server.

In some cases, it's easier for the configuration to be on the server, for
example capturing traffic from two interfaces at once.  In this case, there
are now options for rpcapd to "preselect" which interfaces to capture on,
regardless of how the ExtraHop is configured.

