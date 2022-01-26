+++
title = "The Programmable Data Plane and the OS"
date = 2022-02-22
draft = true
+++

## Background

Over the last decade or so, data networks have become increasingly programmable.
Fixed function network interface cards and switch ASICs – once the only option – are now readily available in various programmable forms. Much of the work in this
space, sometimes referred to “software defined networking” has focused on the
development of new protocols, often skipping the operating system's networking
stack all together.

The programmable data plane also offers potential advantages to the OS network 
stack. First and foremost, network hardware is no longer a black box. This means
that **_interactions between kernel-level network functions and network functions
exposed by hardware can be analyzed and understood as a combined whole_**. A
programmable data plane also democratizes development of kernel-level network
features by putting a community of kernel developers in the driver seat rather
than living at the mercy of proprietary firmware.

A formidable challenge in incorporating a programmable data plane at the OS level
is supporting the large breadth of network protocols that are required. From
servers, to laptops to embedded devices – the number and variety of protocols 
that must work _together_ for the operating system's networking stack to
function effectively presents a different set of challenges than
incorporating a programmable data plane for one-off kernel-bypass programs.

## Network Functions at the Hardware/Software Interface

The following network functions are a few simple examples of how OS-level and
firmware-level network functions interact. In this post we'll refer to firmware
simply as code that executes on a network device independently of the
operating system. The examples presented are nowhere near an exhaustive list.
Take a look at the data sheet for any modern data-center NIC [^1] [^2] [^3], and
you'll find dozens of network functions that are implemented by these devices.

### Checksum Offload

### TCP Offload

### Tunnel Encap/Decap Offload

### Pushing more functionality onto network processing units

Ideally, the central processing unit on a computer is dedicated to executing the
code of programs running on the computer, and spends few cycles as possible
performing network functions. This leaves the execution of network functions to
network processing units (**NPU**). However, for some network functions, the OS
must be aware of a subset of the state involved and how it evolves. This is
called **stateful offload**. Functions that can be completely offloaded to an
NPU and the OS can remain happily oblivious to what's going are referred to as **stateless
offload**.

## The Fragmented state of Data Plane Compilers and Control Interfaces

## An OS-Level Programmable Data Plane Architecture

## Working Backwards from the Ideal Interface

[^1]: [Intel 800 series](https://cdrdv2.intel.com/v1/dl/getContent/639389?explicitVersion=true)

[^2]: [Mellanox ConnectX-6](https://www.mellanox.com/files/doc-2020/pb-connectx-6-dx-en-card.pdf)

[^3]: [Chelsio T6](https://www.chelsio.com/wp-content/uploads/resources/Chelsio-Terminator-6-Brief.pdf)

