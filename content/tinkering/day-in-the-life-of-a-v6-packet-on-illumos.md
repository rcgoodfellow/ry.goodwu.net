+++
title = "A Day in the Life of an IPv6 Packet on illumos"
date = 2022-10-22
+++

This post describes how [IPv6](https://datatracker.ietf.org/doc/html/rfc2460)
packets are transmitted and received on the [illumos](https://illumos.org/)
operating system. We look at the ICMPv6, UDP and TCP protocols.

All of the tinkering shown in this post is done within a networked testbed
environment created by the [Falcon](https://github.com/oxidecomputer/falcon)
tool. A repository of the environment and scripts I used for this post is
available [here](https://github.com/rcgoodfellow/v6pkt-demo).

## ICMPv6

Before any TCP or UDP messages can be exchanged between hosts over IPv6,
[Internet Control Message Protocol Version 6](https://datatracker.ietf.org/doc/html/rfc4443)
packets must be exchanged. In particular,
[Neighbor Discovery](https://datatracker.ietf.org/doc/html/rfc2461)
protocol (NDP) messages, which are embedded in ICMPv6 packets, are exchanged in
order for hosts on the same subnet to tell each other what layer-2 MAC addresses
their layer-3 IPv6 addresses use. This process is generally referred to as
address resolution, and is handled by the
[Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826) (ARP)
in IPv4.

When an application asks the operating system (OS) to send an IPv6 packet, the
OS first checks the destination address of the packet to see if the destination
is on a local subnet. If not, then the OS consults its routing table in search
of a gateway address for a router on the local subnet that can forward the
packet on to its destination. In either case, the OS must determine what the MAC
address of the _nexthop_ IPv6 address is, in order to form an Ethernet frame
with the correct destination to send out on the network.

illumos keeps a table of _neighbor cache entries_ (NCE) that tracks IPv6 to
link-layer address mappings. For Ethernet, the link-layer address is a MAC
address. illumos NCE entries are capable of mapping IPv6 addresses onto other
link-layer protocols, but we'll just be considering Ethernet here.

In the event that the illumos has an IPv6 packet to send, but does not have an
NCE entry that tells it what MAC address to use, the OS must resolve the
destination address using NDP. This involves sending out a _neighbor
solicitation_, and awaiting a corresponding _neighbor advertisement_. Similarly,
it is the responsibility of the operating system to respond to neighbor
solicitations for all of its assigned IPv6 addresses.

The ICMPv6 protocol is also home to the packets employed by the popular
[`ping`](https://illumos.org/man/8/ping)
program. Ping requests are 
[Echo Request](https://datatracker.ietf.org/doc/html/rfc4443#section-4.1)
packets. Ping replies are
[Echo Reply](https://datatracker.ietf.org/doc/html/rfc4443#section-4.2)
packets.

In our exploration of ICMPv6 packet plumbing on illumos we'll look at both NDP
and Echo message types. We'll attempt to send Echo messages to destination
addresses the operating system does not have in its NCE cache, causing an NDP
exchange before sending of the Echo request packets. We'll look at the mechanics
from both the transmitting and receiving side of things.

### Testbed Setup

The testbed environment is a simple two node setup. The nodes are directly
connected to each other.

```
    +=============+               +==============+
    |             |               |              |
    |         *--------*      *--------*         |
    | violin  | vioif0 |------| vioif0 |  piano  |
    |         *--------*      *--------*         |
    |             |               |              |
    +=============+               +==============+
```

Each node is configured with an IPv6 link-local address. For more on illumos
IPv6 address machinery see my other post 
[A Day in the Life of an IPv6 Address on illumos](
/tinkering/a-day-in-the-life-of-an-ipv6-address-on-illumos).

```shell
ipadm create-addr -T addrconf vioif0/v6
```

### Transmitting

To send out a ping message we're going to write a small program. We could use
the `ping` program. But the goal here is to understand how packet flow plumbing
works end to end, including the user space programming interfaces provided by
the operating system. Our little program let's us explore this in under 60 lines
of Rust code. A buildable rust crate for this program is available
[here](https://github.com/rcgoodfellow/v6pkt-demo).

```rust
use clap::Parser;
use ispf::{from_bytes_be, to_bytes_be};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::{transmute, MaybeUninit};
use std::net::{Ipv6Addr, SocketAddrV6};

#[derive(Parser)]
#[clap(version, about)]
struct Args {
    #[clap(value_parser)]
    address: Ipv6Addr,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct EchoMessage {
    typ: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence_number: u16,
}

fn main() {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .expect("new socket");
    transmit(Args::parse().address, &sock);
    receive(&sock);
}

fn transmit(addr: Ipv6Addr, sock: &Socket) {
    let sa: SockAddr = SocketAddrV6::new(addr, 0, 0, 0).into();
    let message = EchoMessage {
        typ: 128,
        identifier: 47,
        ..Default::default()
    };
    let packet_buf = to_bytes_be(&message).expect("serialize message");
    sock.send_to(&packet_buf, &sa).expect("icmp send");
}

fn receive(sock: &Socket) {
    let mut buf = [MaybeUninit::new(0); 1024];
    let (n, sender) = sock.recv_from(&mut buf).expect("icmp recv");
    let buf = unsafe { transmute::<_, [u8; 1024]>(buf) };
    let msg: EchoMessage = from_bytes_be(&buf[..n]).expect("parse icmp");
    println!(
        "reply from {} {:#?}",
        sender.as_socket_ipv6().expect("sender sockaddr").ip(),
        msg,
    );
}
```

On the two computers `violin` and `piano` we have the following addresses

```
root@violin:~# ipadm
ADDROBJ           TYPE     STATE        ADDR
lo0/v4            static   ok           127.0.0.1/8
vioif1/v4         dhcp     ok           192.168.1.201/24
lo0/v6            static   ok           ::1/128
vioif0/v6         addrconf ok           fe80::8:20ff:fe94:4d3a/10
```

```
root@piano:~# ipadm
ADDROBJ           TYPE     STATE        ADDR
lo0/v4            static   ok           127.0.0.1/8
vioif1/v4         dhcp     ok           192.168.1.202/24
lo0/v6            static   ok           ::1/128
vioif0/v6         addrconf ok           fe80::8:20ff:fe01:aead/10
```

When we use our program to send a ping from `violin` to `piano` we see the
following.

```
root@violin:~# ./ping fe80::8:20ff:fe01:aead
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
```

This shows us that in response to our echo message (message type `128`) we got a
reply (message type `128`) from our neighbor with an IPv6 link local address
`fe80::8:20ff:fe01:aead`.

Now let's get into the actual plumbing!

#### Socket Allocation

In the code above, the first thing we do is open up a
[`socket`](https://illumos.org/man/3SOCKET/socket).
The Rust programming interface from the
[socket2](https://docs.rs/socket2/latest/socket2/)
crate we are using provides the same API as the operating system with a bit of
type safety sprinkled in using Rust enumerations and options instead of of
integers. At the end of the day, the `socket2` Rust crate is using the
underlying `socket` function.

On illumos the primary code path for the `socket` function is just a wrapper around a
system call. The
[`socket`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/lib/libsocket/socket/socket.c#53)
function, wraps the
[`_socket_create`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/lib/libsocket/socket/socket.c#93)
function, which wraps the syscall
[`_so_socket`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/lib/libc/common/sys/_so_socket.s#40).
When we land on the other side in the kernel, we arrive at the
[`so_socket`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/socksyscalls.c#95) function. Our Rust code is calling the `socket` function with the following parameters.

- `domain`: [`AF_INET6`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socket.h#300)
- `type`: [`SOCK_RAW`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socket.h#111)
- `protocol`: [`IPPROTO_ICMPV6`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/netinet/in.h#170)

Additionally the `_socket_create` function sets the following values for the
syscall.

- `devpath`: `NULL`
- `version`: [`SOV_DEFAULT`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socketvar.h#383)

Because our `devpath` is `NULL`, the first meaningful thing `so_socket` does is
call
[`socket_create`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon.c#69). 
In `socket_create` the first thing that happens is a
[`sockparams`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socketvar.h#461)
lookup via
[`solookup`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockparams.c#663).
The `sockparams` struct maps the `(family, type, protocol)` triple onto a socket
module or STREAMS device.

The `sockparams` struct contains a
[`smod_info`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socketvar.h#435)
member that contains a `so_create_func_t` function pointer that allows us to
create a socket node using the module our `(family, type, protocol)` triple
mapped to.

Taking a look at what functions get mapped to this pointer, there appear to be
two.

- [`sotpi_create`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/socktpi.c#276)
- [`sock_comm_create_function`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/socksubr.c#254) / [`socket_sonode_create`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon_subr.c#1218)

TPI stands for Transport Provider Interface and appears to be a 
[very old Unix standard](http://www.openss7.org/docs/tpi.pdf).
I'm guessing we're using the `socket_sonode_create` function, but let's use
`dtrace` to find out!

First a quick look to find the exact `dtrace` probe we need.

```
root@violin:~# dtrace  -l | grep socket_sonode_create
57129        fbt            sockfs              socket_sonode_create entry
57130        fbt            sockfs              socket_sonode_create return
```

Now let's run the probe

```
root@violin:~# dtrace  -n 'fbt:sockfs:socket_sonode_create:entry' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:sockfs:socket_sonode_create:entry' matched 1 probe
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1195 has exited
CPU     ID                    FUNCTION:NAME
  1  57129       socket_sonode_create:entry
```

Ok, looks like our intuition was correct. Just as a sanity check let's make sure
that the TPI function is not being called.

```
root@violin:~# dtrace  -n 'fbt:sockfs:sotpi_create:entry' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:sockfs:sotpi_create:entry' matched 1 probe
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1199 has exited
```

Alrighty, no TPI here.

The `socket_sonode_create` function essentially allocates a `sonode` object and
fills in various information depending on the socket parameters object, address
family, etc. See
[`sonode_init`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon.c#557)
for more details. We'll come back to `sonode` properties as they become relevant
for packet transmission using the socket.

#### Sending Packets

The next significant thing that happens in our ping program is a call to
`send_to`. Similar to the socket call, the rust `send_to` method on the `Socket`
object corresponds to the sockets library function
[`sendto`](https://illumos.org/man/3SOCKET/send).

Similar to the `socket` call, `sendto` is a series of wrappers around a syscall
ultimately landing at the `__so_sendto` assembly function definition.

Inside the kernel, the `__so_sendto` call lands us at
[`sendto`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/socksyscalls.c#1466).
The `sendto` function initializes a `uio` data structure and ultimately calls
the
[`sendit`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/socksyscalls.c#1192)
function.

We can see that the first thing that happens in `sendit` is grabbing the
`sonode` that was created in `so_socket` above. Then after a bit of sanity
checking and further data structure setup calls
[`socket_sendmsg`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon.c#317).
This function wraps the `sop_sendmsg` of ``sonode`so_ops`` object. The
``sonode`so_ops`` object comes from a statically defined structure of function
pointers
[`so_sonodeops`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon_sops.c#1934).
The function we are currently looking at is
[`so_sendmsg`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon_sops.c#342).

The first interesting thing that happens here is we are determining if the send
function of this `sonode` is flow controlled via `SO_SND_FLOWCTRLD` and then
waiting until the send queue for the `sonode` is not full so we can send data
through it. Let's use `dtrace` to see if this is happening with ping program.

```
root@violin:~# dtrace  -n 'fbt:sockfs:so_snd_wait_qnotfull:entry' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:sockfs:so_snd_wait_qnotfull:entry' matched 1 probe
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1223 has exited
```

Ok, so the socket being used for sending our ICMPv6 message is not flow
controlled. This makes sense. I suspect we'll see this function fire when we get
to TCP.

Next, ``sonode`so_downcalls`` is inspected to see how we should send the data.
The options here are sending vectored I/O via
[`uio`](https://illumos.org/man/9S/uio)
or just using the basic send path for contiguous data.

These down calls were set up back in the `socket_create` function via a call to
the `SOP_INIT` macro. That macro wraps the ``sonode`so_ops`sop_init`` function
pointer. Recall that ``sonode`so_ops`` is a reference to the static
`so_sonodeops` structure. In that structure `sop_init` points to `so_init` which
is a wrapper for
[`socket_init_common`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/fs/sockfs/sockcommon_subr.c#1268).

In `socket_init_common` the down calls are initialized via
``sockparams`sp_mod_info`smod_proto_create_func``. To understand how this
function gets set, we need to look at the initialization of the underlying
module that provides the socket's data path. The internet device driver
interface (DDI)
[initializes](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/inetddi.c#236)
a socket module registration structure
[`smod_reg_s`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socketvar.h#421).
The `INET_SOCK_PROTO_CREATE_FUNC` is what's of interest here. This macro has
multiple definitions. What definition is used depends on what kernel driver is
including this `inetddi.c` into it's own source and what definition that driver
has for `INET_SOCK_PROTO_CREATE_FUNC` :/.

Currently we're interested in ICMPv6 so we'll be taking a look at the
[`INET_SOCK_PROTO_CREATE_FUNC`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmpddi.c#42)
in the `ip` module. Later on we'll be looking at the `tcp` and `udp` module
definitions of this macro. The
[`rawip_create`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmp.c#5362)
function `INET_SOCK_PROTO_CREATE_FUNC` resolves to in the `ip` module sets the
down calls object to
[`sock_rawip_downcalls`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmp.c#5851).
When we cross reference that instantiation with the
[`sock_downcalls_s`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/sys/socket_proto.h#99)
structure definition, we can see that the ``sock_downcalls_s`sd_send_uio``
member is set to `NULL`. Therefore the send function being used is
``sock_downcalls_s`sd_send`` which resolves to
[`rawip_send`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmp.c#5632).

The `rawip_send` function is partitioned into two primary code blocks for IPv4
and IPv6. After a bit of validation and error checking we land at the
[`icmp_output_newdst`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmp.c#4384)
function.

Now we're getting into the meat and potatoes of sending the packet, starting
with the call to
[`ip_attr_connect`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/conn_opt.c#2531).
At face value, it's rather curious why we would be calling a function whose name
implies a connection on a connectionless protocol like ICMP, but let's dive in
and take a look at what's going on there.

For IPv6, `ip_attr_connect` is mostly a wrapper around
[`ip_set_destination_v6`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip6.c#1957).
In keeping with our present theme of unexpected names, this function does not
set an IPv6 destination. What this function actually does is:

- Get a routing table entry for the destination address, bailing with an error
  if no route is found, or if the route is something like a black hole entry.
- Set the _source_ address for the outgoing packet under certain conditions.
- Creates a destination cache entry (DCE) for the destination address of the
  packet being sent if one does not already exists.
- Gets a neighbor cache entry (NCE) for the destination IPv6 address.

This raises the question of what happens when there is no NCE e.g., we don't
know the MAC address of the destination IPv6 address.

I've been running around in circles for a bit trying to sort this out, so let's
let `dtrace` guide our search a bit. To set things up let's make sure that there
is no NCE for the destination address we'll ping in the kernel.

We can see what the current entries are with `mdb`.

```
root@violin:~# mdb -ke "::walk nce | ::print nce_t nce_addr"
nce_addr = ff02::1:ff01:aead
nce_addr = fe80::8:20ff:fe01:aead
nce_addr = ff02::1:2
nce_addr = ff02::1
nce_addr = ff02::16
nce_addr = ff02::1:ff94:4d3a
nce_addr = fe80::8:20ff:fe94:4d3a
nce_addr = ff02::2
nce_addr = ::ffff:192.168.1.109
nce_addr = ::ffff:192.168.1.2
nce_addr = ::ffff:192.168.1.1
nce_addr = ::ffff:224.0.0.2
nce_addr = ::ffff:192.168.1.255
nce_addr = ::ffff:224.0.0.22
nce_addr = ::ffff:192.168.1.201
nce_addr = ::1
nce_addr = ::ffff:127.0.0.1
```

Here we can see that there is an entry for `fe80::8:20ff:fe01:aead`. When we
`dtrace` the `ire_to_nce` function we see the following.

```
root@violin:~# dtrace  -n 'fbt:ip:ire_to_nce:entry{ stack(); }' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:ip:ire_to_nce:entry' matched 1 probe
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1317 has exited
CPU     ID                    FUNCTION:NAME
  1  53008                 ire_to_nce:entry
              ip`ip_set_destination_v6+0x46b
              ip`ip_attr_connect+0x14a
              ip`icmp_output_newdst+0x1f5
              ip`rawip_send+0x4b7
              sockfs`so_sendmsg+0x24a
              sockfs`socket_sendmsg+0x62
              sockfs`sendit+0x1ab
              sockfs`sendto+0x88
              unix`sys_syscall+0x17d
```

This is the code path we have been walking through up to this point. Now let's
delete the `nce_entry` in the kernel and try again. We can do this by removing
the IP interface associated with these entries.

```
root@violin:~# ipadm delete-if vioif0
Oct 23 20:54:48 in.ndpd[965]: Interface vioif0 has been removed from kernel. in.ndpd will no longer use it
```

This will wipe out our link local IP address, so we need to create it again.

```
root@violin:~# ipadm create-addr -T addrconf vioif0/v6
```

Let's use `mdb` to verify that our target address no longer has an NCE entry.
```
root@violin:~# mdb -ke "::walk nce | ::print nce_t nce_addr"
nce_addr = ff02::1
nce_addr = fe80::8:20ff:fe94:4d3a
nce_addr = ff02::16
nce_addr = ff02::1:ff94:4d3a
nce_addr = ::ffff:192.168.1.109
nce_addr = ::ffff:192.168.1.2
nce_addr = ::ffff:192.168.1.1
nce_addr = ::ffff:224.0.0.2
nce_addr = ::ffff:192.168.1.255
nce_addr = ::ffff:224.0.0.22
nce_addr = ::ffff:192.168.1.201
nce_addr = ff02::2
nce_addr = ::1
nce_addr = ::ffff:127.0.0.1
```

Great, now let's run that `dtrace` above again.

Something interesting to note in the `icmp_output_newdst` function is in the
call to
[`icmp_prepend_header_template`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/icmp.c#3986).
Notice in our application code we are not calculating and setting the ICMP
header checksum. That is done for us in this function. After preparing the
packet for egress, we land at the
[`conn_ip_output`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip_output.c#136)
function.

```
root@violin:~# dtrace  -n 'fbt:ip:ire_to_nce:entry{ stack(); }' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:ip:ire_to_nce:entry' matched 1 probe
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1323 has exited
CPU     ID                    FUNCTION:NAME
  1  53008                 ire_to_nce:entry
              ip`ip_set_destination_v6+0x46b
              ip`ip_attr_connect+0x14a
              ip`icmp_output_newdst+0x1f5
              ip`rawip_send+0x4b7
              sockfs`so_sendmsg+0x24a
              sockfs`socket_sendmsg+0x62
              sockfs`sendit+0x1ab
              sockfs`sendto+0x88
              unix`sys_syscall+0x17d

  1  53008                 ire_to_nce:entry
              ip`ip_output_simple_v6+0x152
              ip`ip_output_simple+0x122
              ip`ndp_xmit+0x27d
              ip`ndp_solicit+0xb3
              ip`ip_ndp_resolve+0xfb
              ip`ip_xmit+0xab5
              ip`ire_send_wire_v6+0x126
              ip`conn_ip_output+0x1d4
              ip`icmp_output_newdst+0x644
              ip`rawip_send+0x4b7
              sockfs`so_sendmsg+0x24a
              sockfs`socket_sendmsg+0x62
              sockfs`sendit+0x1ab
              sockfs`sendto+0x88
              unix`sys_syscall+0x17d
```

Interesting, so now we have two code paths running through `ire_to_nce`. This
was not actually what I was anticipating seeing (which is consistent with the
circles I've been running around in for the past little bit) - but it's
interesting so let's take a look!

The first code path is identical to the case where the NCE for our destination
address is already present. The second code path starts to diverge after the
`icmp_output_newdst` call. We can see that all the way down in `ip_xmit` is
where the logic is to determine if we have an NCE for the destination
address and what to do if we don't.

Tracing `ip_xmit` sheds more light on things.

```
root@violin:~# dtrace  -n 'fbt:ip:ip_xmit:entry{ stack(); }' -c './ping fe80::8:20ff:fe01:aead'
dtrace: description 'fbt:ip:ip_xmit:entry' matched 2 probes
reply from fe80::8:20ff:fe01:aead EchoMessage {
    typ: 129,
    code: 0,
    checksum: 65350,
    identifier: 12032,
    sequence_number: 0,
}
dtrace: pid 1342 has exited
CPU     ID                    FUNCTION:NAME
  3  51734                    ip_xmit:entry
              ip`ire_send_wire_v6+0x126
              ip`conn_ip_output+0x1d4
              ip`icmp_output_newdst+0x644
              ip`rawip_send+0x4b7
              sockfs`so_sendmsg+0x24a
              sockfs`socket_sendmsg+0x62
              sockfs`sendit+0x1ab
              sockfs`sendto+0x88
              unix`sys_syscall+0x17d

  3  51734                    ip_xmit:entry
              ip`ip_postfrag_loopcheck+0x9c
              ip`ire_send_wire_v6+0x126
              ip`ire_send_multicast_v6+0xa6
              ip`ip_output_simple_v6+0x5de
              ip`ip_output_simple+0x122
              ip`ndp_xmit+0x27d
              ip`ndp_solicit+0xb3
              ip`ip_ndp_resolve+0xfb
              ip`ip_xmit+0xab5
              ip`ire_send_wire_v6+0x126
              ip`conn_ip_output+0x1d4
              ip`icmp_output_newdst+0x644
              ip`rawip_send+0x4b7
              sockfs`so_sendmsg+0x24a
              sockfs`socket_sendmsg+0x62
              sockfs`sendit+0x1ab
              sockfs`sendto+0x88
              unix`sys_syscall+0x17d

  3  51734                    ip_xmit:entry
              ip`nce_resolv_ok+0xfa
              ip`nce_process+0x168
              ip`ndp_input_advert+0x373
              ip`ndp_input+0x291
              ip`icmp_inbound_v6+0x532
              ip`ip_fanout_v6+0xf62
              ip`ip_input_local_v6+0x1e
              ip`ire_recv_local_v6+0x131
              ip`ill_input_short_v6+0x472
              ip`ip_input_common_v6+0x283
              ip`ip_input_v6+0x1f
              ip`ip_rput_v6+0x71
              unix`putnext+0x233
              dld`dld_str_rx_fastpath+0x37
              dls`i_dls_link_rx+0x311
              mac`mac_rx_deliver+0x2e
              mac`mac_rx_soft_ring_drain+0x115
              mac`mac_soft_ring_worker+0xa1
              unix`thread_start+0xb
```

This shows that in the process of `ip_xmit`, it was determined that we needed to
send an NDP solicitation, and what we are seeing in terms of `ip_xmit` is the
transmission of that NDP packet, not our ping packet. So let's go figure out
how and where that is being sent.

Looking at the `ip_xmit` code, we see that when the neighbor discovery state is
`ND_INITIAL`, the message block that was sent to `ip_xmit` is queued up via
[`nce_queue_mp`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip_ndp.c#2985).

A bit of poking around in `ip_ndp.c` shows that message block queues attached to
NCEs are transmitted once an NDP round of messages succeeds with 
[`nce_resolv_ok`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip_ndp.c#3099).
And we can actually see that in the third trace above. Just prior to the
`ip_xmit:entry` from `dtrace` we see ``ip`nce_resolv_ok``. So now we have a
complete context for our 3 traces above. The first two are the same trace, since
`ip_xmit` is called twice in the same call stack, the first time in an attempt
to send the desired packet, and the second time to send an NDP request in lieu
of the desired packet. The third trace is kicked off by the reception of an NDP
advertisement in response to the solicitation we sent out, which results in a
successful NCE resolution and thus our initial packet that was queued up waiting
for a good NCE entry goes out the door.

Now it's time to take a look at how packets leave the `ip` module on the way out
the front door. The bulk of this is under the `sendit` in `ip_xmit` when the NDP
state is `REACHABLE`, `STALE`, `DELAY` or `PROBE`. The first thing that happens
is attaching a link-layer header to the outgoing packet using
[`ip_xmit_attach_llhdr`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip.c#12108).
This function checks for a _fastpath_ header located at ``nce`nce_fp_mp``,
and prepends it to the message block. We can see from `mdb` that the fastpath
header is present for the IPv6 address we are pinging. More information on
fastpath can be found in the blog post
[DLPI and the IP Fastpath](http://dtrace.org/blogs/rm/2014/04/03/dlpi-and-the-ip-fastpath/).

```
root@violin:~# mdb -ke "::walk nce | ::print nce_t nce_addr nce_fp_mp"
nce_addr = ff02::2
nce_fp_mp = 0xfffffe0651377a80
nce_addr = ff02::1:ff01:aead
nce_fp_mp = 0xfffffe065a31a380
nce_addr = fe80::8:20ff:fe01:aead
nce_fp_mp = 0xfffffe065a18fa20
<remaining output snipped>
```

After prepending the link-layer header, it's time to send the packet down to the
next layer. How this is accomplished depends on whether or not the IP lower
layer (ILL) for the IP interface we are transmitting on supports direct
transmit. We can use `mdb` to take a look at the ``ill_t`ill_capabilities``
value to see if `ILL_CAPAB_DLD_DIRECT` is set.

```
root@violin:~# mdb -ke "::walk ill | ::print ill_t ill_name ill_inputfn ill_capabilities"
ill_name = 0xfffffe0659ae2308 "vioif0"
ill_inputfn = ill_input_short_v4
ill_capabilities = 0

ill_name = 0xfffffe06587d8d48 "vioif0"
ill_inputfn = ill_input_short_v6
ill_capabilities = 0x30
<non-relevant output snipped>
```

Here we can see that the `ill` for IPv4 has no capabilities - which I suppose
makes sense as there is no IPv4 address assigned to this interface. The
capabilities of the IPv6 `ill` are set to `0x30` which indicates
[`ILL_CAPAB_DLD_DIRECT`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip.h#1418)
that has a value of `0x80` is not enabled.

Curios to know why direct mode is not enabled for this interface as it is
enabled for another interface on this system using the same Ethernet driver, I
found this bit of code for
[`ill_capability_dld_enable`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/inet/ip/ip_if.c#2113)

```c
static void
ill_capability_dld_enable(ill_t *ill)
{
	mac_perim_handle_t mph;
	ASSERT(IAM_WRITER_ILL(ill));
	ill_mac_perim_enter(ill, &mph);
	if (!ill->ill_isv6) {
		ill_capability_direct_enable(ill);
		ill_capability_poll_enable(ill);
	}
	ill_capability_lso_enable(ill);
	ill->ill_capabilities |= ILL_CAPAB_DLD;
	ill_mac_perim_exit(ill, mph);
}
```

So the direct mode capability is never enabled for IPv6 hmm.... Let's try to
figure out why that is. There is a fair amount of indirection going on with this
capability, let's see if `mdb` can give is a picture of what
``ill_t`ill_dld_capab`idc_direct`idd_tx_df`` looks like for a current `ill` on
the system.

```
root@violin:~# mdb -ke "::walk ill | ::print ill_t ill_dld_capab | ::print ill_dld_capab_t idc_direct"
idc_direct = {
    idc_direct.idd_tx_df = str_mdata_fastpath_put
    idc_direct.idd_tx_dh = 0xfffffe065115eab8
    idc_direct.idd_tx_cb_df = mac_client_tx_notify
    idc_direct.idd_tx_cb_dh = 0xfffffe0646de8b38
    idc_direct.idd_tx_fctl_df = mac_tx_is_flow_blocked
    idc_direct.idd_tx_fctl_dh = 0xfffffe0646de8b38
}
```

Ok, there is nothing that stands out as particularly IPv4 specific in
[`str_mdata_fastpath_put`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/io/dld/dld_str.c#864).
Something that is problematic is that ``ill_t`ill_dld_capab`idc_capab_df`` which
gets set to
[`dld_capab`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/io/dld/dld_proto.c#1525)
bails with `ENOTSUP` if `DLD_CAPAB_DIRECT` is being set for a service attachment
point (SAP) with `ETHERTYPE_IPV6`. Dropping down into
[`dld_capab_direct`](https://code.illumos.org/plugins/gitiles/illumos-gate/+/refs/heads/master/usr/src/uts/common/io/dld/dld_proto.c#1356)
we can see ``dld_capab_direct_t`di_tx_df`` getting set to
`str_mdata_fastpath_put` which lines up with what we saw in `mdb` previously.
Let's dig a bit deeper into `str_mdata_fastpath_put` by dropping down into
`DLD_TX`. This is a macro that wraps `mac_tx`. Not immediately seeing any deal
breakers for IPv6 their either ...

**_To be continued ..._**

### Receiving

## UDP
### Transmitting
### Receiving

## TCP
### Transmitting
### Receiving
