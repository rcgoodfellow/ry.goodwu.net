+++
title = "A Day in the Life of an IPv6 Address on illumos"
date = 2022-01-25
+++

This post provides a guided tour of what goes on inside the [illumos](https://illumos.org/) operating system when an [IPv6](https://datatracker.ietf.org/doc/html/rfc2460) address is added. On illumos, the user-space utilities that manage [link-layer](https://datatracker.ietf.org/doc/html/rfc1122#section-2) and [IP-layer](https://datatracker.ietf.org/doc/html/rfc1122#section-3) interfaces are included in the OS. We'll walk through the code that does the following.

- Adds IP-layer interfaces on top of link-layer interfaces in [`ipadm`](https://illumos.org/man/1M/ipadm).
- Manages IP-layer state in `ipmgmtd`.
- Acts as the connective tissue between the link-layer and the IP-layer by implementing the [neighbor discovery protocol](https://datatracker.ietf.org/doc/html/rfc4861) in [`in.ndpd`](https://illumos.org/man/1M/in.ndpd).

On illumos, link-layer and IP-layer interfaces are distinct elements. For brevity, in the rest of this article, I'll refer to the link-layer as L2 and the IP layer as L3. This post will walk through what happens when a [link-local](https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.6) IPv6 address is created. Other types of addresses are touched upon along the way, as the process and code involved is very similar.

## Creating an IPv6 Address

Link-local addresses allow two hosts on the same link to communicate. This could mean two hosts that are directly connected by an [Ethernet](https://en.wikipedia.org/wiki/Ethernet) cable, or it could be a group of hosts connected to an Ethernet switch. A defining characteristic of a _link_ is that L2 frames with a broadcast destination address are delivered to all hosts on the link. This is often referred to as a broadcast domain.

Link-local addresses have the following form.

```
     |<--interface id--->|
fe80::XXXX:XXXX:XXXX:XXXX/10
```

On illumos, link-local addresses are called **_addrconf_** addresses. Before creating one, let's look at the network state on the two machines in our testing lab. This lab has two machines, violin and piano, connected to each other on their first interface and to a common lab network on their second interface.

```
dladm
```

```
LINK        CLASS     MTU    STATE    BRIDGE     OVER
vioif0      phys      1500   up       --         --
vioif1      phys      1500   up       --         --
```

The output above shows we have two L2 interfaces on this machine.

```
ipadm
```

```
ADDROBJ           TYPE     STATE        ADDR
lo0/v4            static   ok           127.0.0.1/8
vioif1/v4         dhcp     ok           10.47.0.186/24
lo0/v6            static   ok           ::1/128
```

This shows that the host has the expected IPv4 and IPv6 localhost addresses on the loopback interface `lo0`, and a DHCP address on the interface `vioif1/v4` which is on our lab network. The L2 interface `vioif0` does not yet have an L3 address, so it does not appear in `ipadm`.

To create a link-local address on the `vioif0` interface, we run the following command.

```
ipadm create-addr -t -T addrconf vioif1/v6
```

The `-t` option indicates this is a temporary address that will not be preserved across reboots. The `-T addrconf` option indicates we're requesting a link-local address. The source code for `ipadm` is [here](https://github.com/illumos/illumos-gate/tree/master/usr/src/cmd/cmd-inet/usr.sbin/ipadm). But before jumping in, we're going to use [`dtrace`](https://illumos.org/books/dtrace/chp-user.html) to give us a high-level view of the code paths involved.

The following is a simple DTrace script that will give us a call graph of every function called in the `libipadm` library that results from our `ipadm` command when combined with the `-F` flag. 

```dtrace
pid$target:libipadm.so::entry,
pid$target:libipadm.so::return {}
```

We can now create a link-local address on `vioif1` and trace the resulting execution through `libipadm` as follows.

```
dtrace -Fs trace.d -c "ipadm create-addr -t -T addrconf vioif0/v6"
```

The following is an abbreviated version of the output from this trace. The reader is encouraged to try this out and look at the full output. The output below will guide us through our tour of the code that creates this local address.

```
<> ipadm_open
<> ipadm_create_addrobj
-> ipadm_create_addr

  -> i_ipadm_lookupadd_addrobj
    <> ipadm_door_call
  <- i_ipadm_lookupadd_addrobj

  -> i_ipadm_create_if
    <> ipadm_if_enabled
    -> i_ipadm_if_pexists
      -> i_ipadm_persist_if_info
        <> ipadm_door_call
      <- i_ipadm_persist_if_info
    <- i_ipadm_if_pexists
    -> i_ipadm_plumb_if
      <> i_ipadm_slifname
      <> ipadm_open_arp_on_udp
      -> i_ipadm_disable_autoconf
        -> i_ipadm_send_ndpd_cmd
          <> ipadm_ndpd_write
          <> ipadm_ndpd_read
        <- i_ipadm_send_ndpd_cmd
      <- i_ipadm_disable_autoconf
    <- i_ipadm_plumb_if
  <- i_ipadm_create_if

  -> i_ipadm_create_ipv6addrs
    -> i_ipadm_create_linklocal
      <> i_ipadm_do_addif
      -> i_ipadm_setlifnum_addrobj
        <> ipadm_door_call
      <- i_ipadm_setlifnum_addrobj
      <> i_ipadm_addrobj2lifname
    <- i_ipadm_create_linklocal
    -> i_ipadm_send_ndpd_cmd
      <> ipadm_ndpd_write
      <> ipadm_ndpd_read
    <- i_ipadm_send_ndpd_cmd
    -> i_ipadm_addr_persist
      <> i_ipadm_add_intfid2nvl
      -> i_ipadm_addr_persist_nvl
        <> ipadm_door_call
      <- i_ipadm_addr_persist_nvl
    <- i_ipadm_addr_persist
  <- i_ipadm_create_ipv6addrs

<- ipadm_create_addr
<> ipadm_destroy_addrobj
<> ipadm_close
```

Before jumping into the code, let's look at the result of our `ipadm create-addr` call.

```
ipadm show-addr vioif0/v6
```

```
ADDROBJ           TYPE     STATE        ADDR
vioif0/v6         addrconf ok           fe80::8:20ff:fe11:bddf/10
```

This address conforms to the format described at the beginning of this section. The interface-id is derived from the MAC address of the L2 interface.

```
dladm show-phys -m vioif0
```

```
LINK         SLOT     ADDRESS            INUSE CLIENT
vioif0       primary  2:8:20:11:bd:df    yes  vioif0
```

This particular way of translating a MAC address into an IPv6 link-local address results in a 64-bit extended unique identifier or [EUI-64](https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.1). It places the two-octet sequence `ff:fe` between the leading and trailing three octets of the 48-bit MAC address, forming a 64-bit identifier. Then the 7th leading bit is inverted. We can see this above, where the leading `2 = 0b00000010` has its 7th bit inverted and becomes `0 = 0b00000000`. 

Five primary things are happening in creating this IP address.

```
┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
│  create   │   │  create   │   │  inform   │   │  create   │   │   addr    │
│  addrobj  │──▶│    if     │──▶│   ndp     │──▶│   addr    │──▶│  persist  │
└───────────┘   └───────────┘   └───────────┘   └───────────┘   └───────────┘
```

### Address Objects

An `addrobj` collects various information about an address as it goes through the stages of creation. This object is passed around to multiple subsystems within `libipadm` as the process of creating the address unfolds. The first step of creating an address is allocating and populating an initial set of fields in this struct in `ipadm_create_addrobj`. The code below only contains one address type `ipadm_ipv6_intfid_s` which is yet another name for IPv6 link-local address on illumos. In the actual `ipadm_addrobj_s` struct, there are several more address types in the `ipadm_addr_u` union that we'll look at later.

```c
struct ipadm_addrobj_s {
        char                    ipadm_ifname[LIFNAMSIZ];
        int32_t                 ipadm_lifnum;
        char                    ipadm_aobjname[IPADM_AOBJSIZ];
        ipadm_addr_type_t       ipadm_atype;
        uint32_t                ipadm_flags;
        sa_family_t             ipadm_af;
        union {
                struct {
                        struct sockaddr_in6     ipadm_intfid;
                        uint32_t                ipadm_intfidlen;
                        boolean_t               ipadm_stateless;
                        boolean_t               ipadm_stateful;
                } ipadm_ipv6_intfid_s;
        } ipadm_addr_u;
};
```

### IP Interfaces

Next comes creating the IP interface. This code path may or may not execute depending on whether an IP interface exists for the specified L2 interface. When an address is requested for an L2 device, the code in `i_ipadm_create_if` checks to see if an IP interface exists for the given L2 interface. If it does, the requested address can be created immediately. If an IP interface does not exist, one must be _plumbed_ onto the L2 interface. This is done in `i_ipadm_plumb_if`.

The process of plumbing an L2 interface for IP is depicted in the following simplified code. Readers are encouraged to look over the actual `i_ipadm_plumb_if` code.

```c
char *ifname; // This is the name of the L2 interface
dlpi_handle_t dh_ip;
int dlpi_fd, mux_fd;

// Open a data link provider interface (DLPI) instance on the L2 interface.
// A DLPI instance can be thought of as an L2 analogue to a socket.
dlpi_open(ifname, &dh_ip, DLPI_NOATTACH);
dlpi_fd = dlpi_fd(dh_ip);

// Push the IP STREAMS module onto the L2 device
ioctl(dlpi_fd, I_PUSH, IP_MOD_NAME);

// This call issues a SIOCSLIFNAME ioctl to the kernel. This sets the ill_name 
// entry in the kernel that we we'll look at with `mdb` in the next section. To 
// see this in action check out the kernel function `ip_sioctl_slifname`.
i_ipadm_slifname(iph, ifname, NULL, IFF_IPV6, dlpi_fd, 0);

// Open the UDP pseudo-device to get a reference to the IP multiplexer. Then
// link the DLPI+IP stream below the multiplexer.
mux_fd = open(UDP6_DEV_NAME, O_RDRW);
ioctl(mux_fd, I_PLINK, dlpi_fd);
```

The STREAMS plumbing that's being done here is visualized in the diagram below. The diagram is read from left to right. The `dlpi_open` call in the code above gives us a reference to a DLPI instance that is associated with the physical device `vioif1` (going back to our original `ipadm create-addr` call at the beginning of this section). The `ioctl(dlpi_fd, I_PUSH, IP_MOD_NAME)` pushes the IP module onto the DLPI driver instance. Then `open(UDP6_DEV_NAME, O_RDRW)` gets us a reference to the system's UDP STREAMS module which is attached to the system's IP multiplexer. Then we use `ioctl(mux_fd, I_PLINK, dlpi_fd)` to attach the data-link driver for `vioif1` into the system's IP multiplexer.

```
            │            │              ┏━━━━━━━━┓    │       ┌────────┐       
            │            │              ┃  UDP   ┃    │       │  UDP   │       
            │            │              ┃ module ┃    │       │ module │       
            │            │              ┗━━━━━━━━┛    │       └────────┘       
            │            │              ┏━━━━━━━━┓    │       ┌────────┐       
            │            │              ┃   IP   ┃    │       │   IP   │       
            │            │           ┏━━┫ driver ┣━━┓ │ ┏━━━━━┫ driver ┣━━━━━━┓
            │            │           ┃  ┗━━━━━━━━┛  ┃ │ ┃     └────────┘      ┃
            │            │           ┃IP multiplexer┃ │ ┃   IP multiplexer    ┃
            │ ┏━━━━━━━━┓ │ ┌────────┐┃  ┏━━━━━━━━┓  ┃ │ ┃┏━━━━━━━━┓ ┌────────┐┃
            │ ┃   IP   ┃ │ │   IP   │┗━━┫   IP   ┣━━┛ │ ┗┫   IP   ┣━┫   IP   ┣┛
            │ ┃ module ┃ │ │ module │   ┃ module ┃    │  ┃ module ┃ │ module │ 
            │ ┗━━━━━━━━┛ │ └────────┘   ┗━━━━━━━━┛    │  ┗━━━━━━━━┛ └────────┘ 
 ┏━━━━━━━━┓ │ ┌────────┐ │ ┌────────┐   ┏━━━━━━━━┓    │  ┌────────┐ ┌────────┐ 
 ┃  DLPI  ┃ │ │  DLPI  │ │ │  DLPI  │   ┃  DLPI  ┃    │  │  DLPI  │ │  DLPI  │ 
 ┃ driver ┃ │ │ driver │ │ │ driver │   ┃ driver ┃    │  │ driver │ │ driver │ 
 ┗━━━━━━━━┛ │ └────────┘ │ └────────┘   ┗━━━━━━━━┛    │  └────────┘ └────────┘ 
 ╔════════╗ │ ╔════════╗ │ ╔════════╗   ╔════════╗    │  ╔════════╗ ╔════════╗ 
 ║ vioif1 ║ │ ║ vioif1 ║ │ ║ vioif1 ║   ║ vioif0 ║    │  ║ vioif1 ║ ║ vioif0 ║ 
 ╚════════╝ │ ╚════════╝ │ ╚════════╝   ╚════════╝    │  ╚════════╝ ╚════════╝ 
----------------------------------------------------------------------------------
 dlpi_open  │   I_PUSH   │    open(UDP6_DEV_NAME)     │         I_PLINK        
```

When the IP module for the L2 interface being plumbed is created via `I_PUSH`, the module's open routine `ip_open` is called. This results in `ip_modopen` being called, which creates an **_IP lower level structure_** (`ill`) in the kernel's `ill` list. The `ill` is used in IP address assignment and will be discussed in the next section.

### Addresses

The function that actually creates the link-local address is `i_ipadm_create_linklocal`.  This function eventually makes an `ioctl` down to the kernel with the `SIOCSLIFPREFIX` command, which is handled by the `ip_sioctl_prefix` kernel function. This kernel function first gets a reference to the **_IP lower level structure_** (`ill`) from the **_IP interface structure_** (`ipif`) that is provided to the `ioctl` handler. The `ill` contains something called an `ill_token` that contains the IPv6 ID for the interface in question. This IPv6 ID is combined with the `fe80` prefix generated in `i_ipadm_create_linklocal` to create the complete link-local address.

There is another development tool for illumos that allows us to look at all the `ipif`/`ill` entries in the kernel called the modular debugger [`mdb`](https://illumos.org/books/mdb/preface.html). Let's use this tool to look at the `ill_token` value for each `ill` entry in the kernel.

```
mdb -k -e "::walk ill | ::print ill_t ill_isv6 ill_name ill_token"
```

```
ill_isv6 = 0
ill_name = 0xfffffe038731c368 "lo0"
ill_token = ::

ill_isv6 = 0
ill_name = 0xfffffe038e13c288 "vioif0"
ill_token = ::

ill_isv6 = 0
ill_name = 0xfffffe0386ebb308 "vioif1"
ill_token = ::

ill_isv6 = 0x1
ill_name = 0xfffffe03873f9fa8 "lo0"
ill_token = ::

ill_isv6 = 0x1
ill_name = 0xfffffe0390e9ad48 "vioif0"
ill_token = ::8:20ff:fe11:bddf
ill_isv6 = 0x1

ill_name = 0xfffffe03890a9d48 "vioif1"
ill_token = ::8:20ff:fed7:fccf
```

This shows us that we have 6 `ill` objects. There are two for each interface, one for IPv4 and one for IPv6. Let's take a closer look at the `mdb` call.

```
         / Target the kernel for debugging
        /
       /  / Execute the following command
      /  /
     /  /
mdb -k -e "::walk ill | ::print ill_t ill_isv6 ill_name ill_token"
           \      \   \ \       \     \-------------------------/
            \      \   \ \       \          members to print
             \      \   \ \       \
              \      \   \ \       \ interpret the address bing printed as an
               \      \   \ \        ill_t kernel data structure
                \      \   \ \ 
                 \      \   \ \ print the data at the address piped in from the
                  \      \   \  walk command
                   \      \   \
                    \      \   \ pipe the output of walk to the print command
                     \      \
                      \      \ select the ill walker
                       \
                        \ use the walk command to iterate over a list in the 
                            kernel
```

There are several other walkers we can use to look at IP state in the kernel. Here are a few.

```
mdb -k -e "::walkers" | egrep "(^ip|^ill)"
```

```
ill                      - walk active ill_t structures for all stacks
illif                    - walk list of ill interface types for all stacks
illif_stack              - walk list of ill interface types
ip_conn_cache            - walk the ip_conn_cache cache
ip_minor_arena_la_1      - walk the ip_minor_arena_la_1 cache
ip_minor_arena_sa_1      - walk the ip_minor_arena_sa_1 cache
ip_stacks                - walk all the ip_stack_t
ipif                     - walk list of ipif structures for all stacks
ipif_list                - walk the linked list of ipif structures for a given ill
ipp_action               - walk the ipp_action cache
ipp_mod                  - walk the ipp_mod cache
ipp_packet               - walk the ipp_packet cache
ipsec_actions            - walk the ipsec_actions cache
ipsec_policy             - walk the ipsec_policy cache
ipsec_selectors          - walk the ipsec_selectors cache
iptun_cache              - walk the iptun_cache cache
```

Additionally there are a set of built in debugger commands that are also available for inspecting IP state in the kernel.

```
mdb -k -e "::dcmds" | egrep "(^ip|^ill)"
```

```
ill                      - display ill_t structures
illif                    - display or filter IP Lower Level InterFace structures
ip6hdr                   - display an IPv6 header
iphdr                    - display an IPv4 header
ipif                     - display ipif structures
```

### NDP Interaction

In creating a link-local IPv6 address, NDP interactions occur in two places, which is readily seen in the DTrace call graph above. The first is when the address is being plumbed. Here, `ipadm_disable_autoconf` is called. This is done because at the time an IP address is being plumbed, it's not clear if any sort of NDP interaction will be needed. For example, if the interface is plumbed for a static IPv6 address, there is no need to kick off any NDP process. The decision on whether NDP should attempt to autoconfigure an IP interface is made in `i_ipadm_create_ipv6addrs`, if the `ipadm_stateless` or `ipadm_stateful` member is set to true then a message will be sent to `ndpd` to try to autoconfigure the address for the device. If we look back to the first bit of code along the IP address creation path we looked at `ipadm_create_addrobj` we see that for link-local addresses both `ipadm_stateless` and `ipadm_stateful` are set to true.

If the `ipadm_stateless` member is true, [IPv6 stateless autoconfiguration](https://www.rfc-editor.org/rfc/rfc4862) (SLAAC) will be performed. If the interface is connected to an IPv6 capable router delegating a prefix, an EUI-64 based IPv6 [ULA](https://datatracker.ietf.org/doc/html/rfc4193) will be assigned to the interface. This address combines the prefix the router advertised and the same EUI-64 interface ID that was computed for the link-local address discussed earlier.

If the `ipadm_stateful` member is true, a [DHCPv6](https://datatracker.ietf.org/doc/html/rfc8415) client will be started. Stateless and stateful configurations are not mutually exclusive. They can be used side by side.