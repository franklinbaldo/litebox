# A LiteBox Platform for running LiteBox in Hyper-V VTL1 kernel space

> [!WARNING]
> This crate is work in progress. Currently, it is a copy of
> `litebox_platform_linux_kernel`.

In the HEKI/HVCI port–adapter architecture this crate is the **enforcement
adapter plus VSM core**. It owns the low-level enforcement primitives (frame
reservation/protection, privileged VTL0 mappings, ringbuffer and
platform-root-key installers, control-register locking, AP boot) and exposes
them to the HEKI/HVCI algorithms through `PlatformHekiEnforcer`, its
implementation of the `litebox_heki::HekiEnforcer` port. The enforcement
primitives are private; the only public surface is the adapter. The generic
HEKI/HVCI algorithms themselves live in `litebox_heki`.
