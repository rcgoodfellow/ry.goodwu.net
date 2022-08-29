+++
title = "Debugging a Core Dump with MDB"
date = 2022-08-29
+++

Our story begins
[here](https://github.com/oxidecomputer/propolis/blob/9952e9701d5d89faa8fe9371a6dc273da9fff6e6/propolis/src/hw/virtio/softnpu.rs#L802-L807).

```rust
fn queue_notify(&self, vq: &Arc<VirtQueue>, ctx: &DispCtx) {
    let handle = tokio::runtime::Handle::current();
    let _guard = handle.enter();
    futures::executor::block_on(self.handle_guest_virtio_request(vq, ctx));
}
```

We've landed in a callback we do not control. This callback is not `async` and
we need to call some `async` code. We know that the process we're running in has
a tokio runtime. So we get a handle to that runtime, enter it and attempt to
block on a future.

When we reach this code, the process we are running in crashes and dumps its
core. There are a number of things to be learned from the core file. The
following analysis is done with the illumos `mdb` tool. A good guide on `mdb`
can be found [here](https://illumos.org/books/dev/debugging.html#core-dumps)

The first thing the core file tells us is that we are in fact experiencing a
segfault.

```
> ::status
debugging core file of propolis-server (64-bit) from masaka
file: /home/ry/src/propolis/target/release/propolis-server
initial argv: /home/ry/src/propolis/target/release/propolis-server run .falcon/router.toml [:
threading model: native threads
status: process terminated by SIGSEGV (Segmentation Fault), addr=fffffbffc44dced0
```

A stack trace shows us that `the Future::poll` method is the point of explosion,
which is a few calls down the chain from our `queue_notify` call.

```
> $G
> > $C
fffffbffc67fe870 <core::future::from_generator::GenFuture<T> as core::future::future::Future>::poll::h0a10623d62628f3a+0x19a()
fffffbffc67fe8b0 std::thread::local::LocalKey<T>::with::he924ca0bd4e6d9cf+0x56()
fffffbffc67fefd0 futures_executor::local_pool::block_on::h7b551178601388b4+0x4c()
fffffbffc67ff700 <propolis::hw::virtio::softnpu::PciVirtioSoftNPUPort as propolis::hw::virtio::VirtioDevice>::queue_notify::h2900034107523958+0x66()
fffffbffc67ff780 propolis::hw::virtio::pci::PciVirtioState::legacy_write::h683ad0199a8250fb+0x274()
fffffbffc67ff900 propolis::hw::virtio::pci::<impl propolis::hw::pci::device::Device for D>::bar_rw::{{closure}}::hea30c7837f72dad6+0x1aa()
fffffbffc67ffa80 propolis::util::regmap::RegMap<ID>::process::h3d39f905a5a91b8b+0x171()
fffffbffc67ffb50 propolis::hw::pci::device::<impl propolis::hw::pci::Endpoint for D>::bar_rw::h883683c8494c42ce+0x134()
fffffbffc67ffc50 propolis::pio::PioBus::handle_out::h0f978df375855073+0x2aa()
fffffbffc67ffe20 propolis::vcpu_run_loop::h5a6c9e2b54e47a88+0x286()
fffffbffc67ffe50 core::ops::function::FnOnce::call_once{{vtable.shim}}::h96a1f70aa2cd73b4+0x1e()
fffffbffc67ffee0 std::sys_common::backtrace::__rust_begin_short_backtrace::h0c5e358dfc29343a +0x90()
fffffbffc67fff60 core::ops::function::FnOnce::call_once{{vtable.shim}}::hffcdb87c11bdff96+0x95()
fffffbffc67fffb0 std::sys::unix::thread::Thread::new::thread_start::h5ec8d723f4048251+0x27()
fffffbffc67fffe0 libc.so.1`_thrp_setup+0x6c(fffffbffee0e1a40)
fffffbffc67ffff0 libc.so.1`_lwp_start()
```

**pro-tip:** the `$G` here turns on demangling support in `mdb` without which
your eyes will bleed over the rust compilers mangling of method names.

Let's take a closer look at the point of explosion. In the below output `Future`
is substituted for `<core::future::from_generator::GenFuture<T> as
core::future::future::Future>` to make the output a bit more readable.

Below we're asking `mdb` to disassemble instructions around the instruction
pointer at the time of the crash.  `mdb` highlights the function that
segfaulted, which does not go well with markdown code blocks, so I've identified
the crashing line here with a sequence of exclamation points.


```
> <rip::dis -n 0xe
Future::poll::h0a10623d62628f3a+0x151:    movq   0xc0(%r14),%rdi
Future::poll::h0a10623d62628f3a+0x158:    call   *0x18(%rax)
Future::poll::h0a10623d62628f3a+0x15b:    movq   0x28(%r15),%rsi
Future::poll::h0a10623d62628f3a+0x15f:    testq  %rsi,%rsi
Future::poll::h0a10623d62628f3a+0x162:    je     +0x34e   <Future::poll::h0a10623d62628f3a+0x4b6>
Future::poll::h0a10623d62628f3a+0x168:    movq   0x18(%r14),%rbx
Future::poll::h0a10623d62628f3a+0x16c:    movl   (%rbx),%edx
Future::poll::h0a10623d62628f3a+0x16e:    movq   0x98(%r14),%rax
Future::poll::h0a10623d62628f3a+0x175:    movq   %rax,-0xa0(%rbp)
Future::poll::h0a10623d62628f3a+0x17c:    movups 0x88(%r14),%xmm0
Future::poll::h0a10623d62628f3a+0x184:    movaps %xmm0,-0xb0(%rbp)
Future::poll::h0a10623d62628f3a+0x18b:    movq   0x30(%r15),%rax
Future::poll::h0a10623d62628f3a+0x18f:    leaq   -0x58(%rbp),%rdi
Future::poll::h0a10623d62628f3a+0x193:    leaq   -0xb0(%rbp),%rcx
Future::poll::h0a10623d62628f3a+0x19a:    call   *0x18(%rax) !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Future::poll::h0a10623d62628f3a+0x19d:    cmpq   $0x0,-0x58(%rbp)
Future::poll::h0a10623d62628f3a+0x1a2:    je     +0x46    <Future::poll::h0a10623d62628f3a+0x1ea>
Future::poll::h0a10623d62628f3a+0x1a4:    leaq   0x8(%rbx),%rcx
Future::poll::h0a10623d62628f3a+0x1a8:    addq   $0x30,%rbx
Future::poll::h0a10623d62628f3a+0x1ac:    movq   -0x38(%rbp),%rax
Future::poll::h0a10623d62628f3a+0x1b0:    movq   %rax,-0x60(%rbp)
Future::poll::h0a10623d62628f3a+0x1b4:    movups -0x58(%rbp),%xmm0
Future::poll::h0a10623d62628f3a+0x1b8:    movups -0x48(%rbp),%xmm1
Future::poll::h0a10623d62628f3a+0x1bc:    movaps %xmm1,-0x70(%rbp)
Future::poll::h0a10623d62628f3a+0x1c0:    movaps %xmm0,-0x80(%rbp)
Future::poll::h0a10623d62628f3a+0x1c4:    movl   -0x30(%rbp),%edx
Future::poll::h0a10623d62628f3a+0x1c7:    leaq   -0x80(%rbp),%rdi
Future::poll::h0a10623d62628f3a+0x1cb:    movq   %rbx,%rsi
Future::poll::h0a10623d62628f3a+0x1ce:    call   +0x233ed <propolis::hw::virtio::softnpu::PciVirtioSoftNPUPort::handle_packet_to_ext_port::h4103b5a93ebf77ce>
```

Here we see the crashing instruction is `call *0x18(%rax)`.  We can see what the
value of `rax` is by dumping the registers at the time of the crash.

```
> $r
%rax = 0xfffffbffc44dceb8       %r8  = 0x0000000000000000
%rbx = 0x0000000002c2c3f0       %r9  = 0x0000000016ba6f00
%rcx = 0xfffffbffc67fe7c0       %r10 = 0x0000000000000501
%rdx = 0x0000000000000000       %r11 = 0x0000000000000000
%rsi = 0x0000000002f5b550       %r12 = 0x0000000000000063
%rdi = 0xfffffbffc67fe818       %r13 = 0xfffffbffc67fe818
                                %r14 = 0xfffffbffc67fe8c8
                                %r15 = 0x0000000002c8f5c0

%cs = 0x0053    %fs = 0x0000    %gs = 0x0000
%ds = 0x004b    %es = 0x004b    %ss = 0x004b

%rip = 0x000000000139a03a <core::future::from_generator::GenFuture<T> as core::future::future::Future>::poll::h0a10623d62628f3a+0x19a
%rbp = 0xfffffbffc67fe870
%rsp = 0xfffffbffc67fe7a0

%rflags = 0x00010206
  id=0 vip=0 vif=0 ac=0 vm=0 rf=1 nt=0 iopl=0x0
  status=<of,df,IF,tf,sf,zf,af,PF,cf>

%gsbase = 0x0000000000000000
%fsbase = 0xfffffbffee0e1a40
%trapno = 0xe
   %err = 0x4
```

So here we see the value of `rax` is `0xfffffbffc44dceb8` and if we add an
offset of `0x18` to that which is what the call above is doing, we land at an
address of `fffffbffc44dced0` which is what our `::status` dcmd above reported
as the segfault address.

In the disassembly above we can see a call to `handle_packet_to_ext_port`. The
corresponding rust code looks like
[this](https://github.com/oxidecomputer/propolis/blob/9952e9701d5d89faa8fe9371a6dc273da9fff6e6/propolis/src/hw/virtio/softnpu.rs#L602-L620).

```rust
fn handle_guest_packet<'a>(
    index: usize,
    mut pkt: packet_in<'a>,
    data_handles: &Vec<dlpi::DlpiHandle>,
    pipeline: &mut Box<dyn Pipeline>,
    log: &Logger,
) {
    match pipeline.process_packet(index as u8, &mut pkt) {
        Some((mut out_pkt, port)) => {
            Self::handle_packet_to_ext_port(
                &mut out_pkt,
                data_handles,
                port,
                &log,
            );
        }
        None => {}
    };
}
```

In the assembly code there is only one control flow instruction between the call
to `handle_packet_to_ext_port` and the site of our crash. This must be the match
statement in the code above which means that the crashing call must be the call
to `process_packet`.

So now the question becomes why is the call to the pipeline a segmentation
fault. To answer this question we need to look at where the
`pipeline::process_packet` address comes from. This is a dynamically loaded
program trait object. The loading code looks like
[this](https://github.com/oxidecomputer/propolis/blob/9952e9701d5d89faa8fe9371a6dc273da9fff6e6/propolis/src/hw/virtio/softnpu.rs#L1397-L1425).

```rust
async fn load_program(
    pipeline: Arc<tokio::sync::Mutex<Option<Box<dyn Pipeline>>>>,
    log: Logger,
) {

    let lib = match unsafe { libloading::Library::new("/tmp/p4.so") } {
        Ok(l) => l,
        Err(e) => {
            warn!(log, "failed to load p4 program: {}", e);
            return;
        }
    };
    let func: libloading::Symbol<
        unsafe extern "C" fn() -> *mut dyn p4rs::Pipeline,
        > = match unsafe { lib.get(b"_main_pipeline_create") } {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    log,
                    "failed to load _main_pipeline_create func: {}", e
                );
                return;
            }
        };

    let mut pl = pipeline.lock().await;
    let _ = pl.insert(unsafe { Box::from_raw(func()) });
}
```

Reading this code now with the insight of where the crash is occurring, I have a
guess as to what's happening. At the end of this function the `lib` function
gets dropped. Which may unload from this process' memory space, the pipeline
implementation we are attempting to process packets with at the site of the
crash. A look at the [drop
implementation](https://github.com/nagisa/rust_libloading/blob/master/src/os/unix/mod.rs#L342-L348)
for the internal `Library` data structure used by `libloading`, we see that
`dlclose` is called on drop.

From the man page of `dlclose`.

> Once an object has been closed by dlclose(), referencing symbols contained in
> that object can cause undefined behavior.

`dlclose`  removes any objects from a corresponding `dlopen`  from the address
space of the calling process. This is consistent with what we are seeing.
