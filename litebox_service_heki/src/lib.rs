#![no_std]

//! HEKI/HVCI + VSM service. Owns VSM dispatch and HEKI enforcement policy on
//! top of a platform-provided hypercall trait.

extern crate alloc;
