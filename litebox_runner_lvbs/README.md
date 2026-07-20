# A LiteBox Runner for running LiteBox in Hyper-V VTL1 kernel space

> [!WARNING]
> This crate is work in progress.

In the HEKI/HVCI port–adapter architecture this crate is the **composition
root**. It wires the platform's `PlatformHekiEnforcer` adapter to the generic
HEKI/HVCI algorithms in `litebox_heki`, owns the single long-lived `HekiState`,
and dispatches VSM policy functions to those algorithms while forwarding the
VSM-core arms (`EnableAPsVtl`/`BootAPs`/`LockRegs`) directly to the platform. It
also provides the OP-TEE dispatch, page-table glue, and panic handler.
