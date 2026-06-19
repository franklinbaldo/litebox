// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Implementation of pseudo TAs (PTAs) which export system services as
//! the functions of built-in TAs.

use crate::{Task, UserConstPtr, UserMutPtr};
use alloc::vec;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use litebox::mm::linux::PAGE_SIZE;
use litebox::platform::{
    DerivedKeyError, DerivedKeyProvider, KDFParams, RawConstPointer as _, RawMutPointer as _,
};
use litebox::utils::TruncateExt;
use litebox_common_optee::{
    HUK_SUBKEY_MAX_LEN, HukSubkeyUsage, LdelfMapFlags, TeeParamType, TeeResult, TeeUuid, UteeParams,
};
use num_enum::TryFromPrimitive;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const PTA_SYSTEM_UUID: TeeUuid = TeeUuid {
    time_low: 0x3a2f_8978,
    time_mid: 0x5dc0,
    time_hi_and_version: 0x11e8,
    clock_seq_and_node: [0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc],
};

const PTA_SYSTEM_ADD_RNG_ENTROPY: u32 = 0;
const PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY: u32 = 1;
const PTA_SYSTEM_MAP_ZI: u32 = 2;
const PTA_SYSTEM_UNMAP: u32 = 3;
const PTA_SYSTEM_OPEN_TA_BINARY: u32 = 4;
const PTA_SYSTEM_CLOSE_TA_BINARY: u32 = 5;
const PTA_SYSTEM_MAP_TA_BINARY: u32 = 6;
const PTA_SYSTEM_COPY_FROM_TA_BINARY: u32 = 7;
const PTA_SYSTEM_SET_PROT: u32 = 8;
const PTA_SYSTEM_REMAP: u32 = 9;
const PTA_SYSTEM_DLOPEN: u32 = 10;
const PTA_SYSTEM_DLSYM: u32 = 11;
const PTA_SYSTEM_GET_TPM_EVENT_LOG: u32 = 12;
const PTA_SYSTEM_SUPP_PLUGIN_INVOKE: u32 = 13;

// subject to change. This is not an official system PTA command ID.
const PTA_SYSTEM_DERIVE_TA_SVN_KEY_STACK: u32 = 14;

/// Minimum size of a derived key in bytes.
const TA_DERIVED_KEY_MIN_SIZE: usize = 16;
/// Maximum size of a derived key in bytes.
const TA_DERIVED_KEY_MAX_SIZE: usize = 32;
/// Maximum size of extra data for key derivation in bytes.
const TA_DERIVED_EXTRA_DATA_MAX_SIZE: usize = 1024;
/// Maximum number of keys in SVN key stack.
const SVN_KEY_STACK_MAX_SIZE: u32 = 4096;

/// `PTA_SYSTEM_*` command ID from `optee_os/lib/libutee/include/pta_system.h`
#[derive(Clone, Copy, TryFromPrimitive)]
#[repr(u32)]
pub enum PtaSystemCommandId {
    AddRngEntropy = PTA_SYSTEM_ADD_RNG_ENTROPY,
    DeriveTaUniqueKey = PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
    MapZi = PTA_SYSTEM_MAP_ZI,
    Unmap = PTA_SYSTEM_UNMAP,
    OpenTaBinary = PTA_SYSTEM_OPEN_TA_BINARY,
    CloseTaBinary = PTA_SYSTEM_CLOSE_TA_BINARY,
    MapTaBinary = PTA_SYSTEM_MAP_TA_BINARY,
    CopyFromTaBinary = PTA_SYSTEM_COPY_FROM_TA_BINARY,
    SetProt = PTA_SYSTEM_SET_PROT,
    Remap = PTA_SYSTEM_REMAP,
    Dlopen = PTA_SYSTEM_DLOPEN,
    Dlsym = PTA_SYSTEM_DLSYM,
    GetTpmEventLog = PTA_SYSTEM_GET_TPM_EVENT_LOG,
    SuppPluginInvoke = PTA_SYSTEM_SUPP_PLUGIN_INVOKE,
    DeriveTaSvnKeyStack = PTA_SYSTEM_DERIVE_TA_SVN_KEY_STACK,
}

/// Checks whether a given TA is a (system) PTA and its parameter is valid.
pub fn is_pta(ta_uuid: &TeeUuid, params: &UteeParams) -> bool {
    // TODO: consider other PTAs
    *ta_uuid == PTA_SYSTEM_UUID
        && params.get_type(0).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(1).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(2).is_ok_and(|t| t == TeeParamType::None)
        && params.get_type(3).is_ok_and(|t| t == TeeParamType::None)
}

// TODO: replace it with a proper implementation.
pub fn close_pta_session(_ta_session_id: u32) {}

/// Check whether a given session ID is associated with a PTA.
pub fn is_pta_session(ta_sess_id: u32) -> bool {
    ta_sess_id == crate::SessionIdPool::get_pta_session_id()
}

type HmacSha256 = Hmac<Sha256>;

impl Task {
    /// Handle a command of the system PTA.
    pub fn handle_system_pta_command(
        &self,
        cmd_id: u32,
        params: &mut UteeParams,
    ) -> Result<(), TeeResult> {
        match PtaSystemCommandId::try_from(cmd_id).map_err(|_| TeeResult::BadParameters)? {
            PtaSystemCommandId::DeriveTaUniqueKey => self.derive_ta_unique_key(params),
            PtaSystemCommandId::DeriveTaSvnKeyStack => self.derive_ta_svn_key_stack(params),
            PtaSystemCommandId::MapZi => self.system_map_zi(params),
            PtaSystemCommandId::Unmap => self.system_unmap(params),
            _ => {
                #[cfg(debug_assertions)]
                todo!("support other system PTA commands {cmd_id}");
                #[cfg(not(debug_assertions))]
                Err(TeeResult::NotSupported)
            }
        }
    }

    fn system_map_zi(&self, params: &mut UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{None, ValueInout, ValueInput};

        if !params.has_types([ValueInput, ValueInout, ValueInput, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (num_bytes_u64, flags_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let (addr_hi, addr_lo) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let (pad_begin_u64, pad_end_u64) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;

        let mut addr = ((addr_hi << 32) | addr_lo).trunc();
        self.sys_map_zi(
            UserMutPtr::<usize>::from_usize((&mut addr as *mut usize) as usize),
            num_bytes_u64.trunc(),
            pad_begin_u64.trunc(),
            pad_end_u64.trunc(),
            LdelfMapFlags::from_bits_truncate(flags_u64.trunc()),
        )?;

        params
            .set_values(1, (addr as u64) >> 32, (addr as u64) & 0xffff_ffff)
            .map_err(|_| TeeResult::BadParameters)?;
        Ok(())
    }

    fn system_unmap(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{None, ValueInput};

        if !params.has_types([ValueInput, ValueInput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (size_u64, must_be_zero) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        if must_be_zero != 0 {
            return Err(TeeResult::BadParameters);
        }

        let (addr_hi, addr_lo) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let addr = ((addr_hi << 32) | addr_lo).trunc();
        let size: usize = size_u64.trunc();
        let size = size
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(TeeResult::BadParameters)?;

        self.sys_munmap(UserMutPtr::<u8>::from_usize(addr), size)
            .map_err(|_| TeeResult::BadParameters)
    }

    /// Derives a unique key for a TA using HUK.
    ///
    /// This follows the OP-TEE `system_derive_ta_unique_key` implementation from
    /// `core/pta/system.c`.
    fn derive_ta_unique_key(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None};

        if !params.has_types([MemrefInput, MemrefOutput, None, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.trunc();

        let (subkey_addr, subkey_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let subkey_size: usize = subkey_size_u64.trunc();

        if extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&subkey_size)
            || (extra_data_size > 0 && extra_data_addr == 0)
            || subkey_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        let extra_data = if extra_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            let extra_data_ptr = UserConstPtr::<u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let subkey_ptr = UserMutPtr::<u8>::from_usize(subkey_addr.trunc());

        // subkey = KDF(huk, usage || ta_uuid || extra_data)
        let ta_uuid_bytes = self.ta_app_id.to_le_bytes();
        let mut subkey_buf = Zeroizing::new(vec![0u8; subkey_size]);
        self.huk_subkey_derive(
            HukSubkeyUsage::UniqueTa,
            &[&ta_uuid_bytes, &extra_data],
            &mut subkey_buf,
        )
        .and_then(|()| {
            subkey_ptr
                .copy_from_slice(0, &subkey_buf)
                .ok_or(TeeResult::AccessDenied)
        })
    }

    /// Derives a stack of unique keys for a TA, one for each possible
    /// Secure Version Number (SVN) value up to a maximum.
    ///
    /// The key derivation follows a two-stage process:
    /// 1. First stage: KDF(huk, uuid || extra_data) -> base key
    /// 2. Second stage: Iterate from max SVN down to 0, chaining keys:
    ///    - Key\[max\] = HMAC(base_key, max)
    ///    - Key\[n\] = HMAC(Key\[n+1\], n)
    ///
    /// Only keys for SVN values <= current TA version are copied to output.
    fn derive_ta_svn_key_stack(&self, params: &UteeParams) -> Result<(), TeeResult> {
        use TeeParamType::{MemrefInput, MemrefOutput, None, ValueInput};
        // Validate parameter types:
        // [in]  params[0].value.a         Size of each key
        // [in]  params[0].value.b         Number of keys to derive
        // [in]  params[1].memref.buffer   Extra data for key derivation
        // [in]  params[1].memref.size     Extra data size
        // [out] params[2].memref.buffer   Output buffer for key stack
        // [out] params[2].memref.size     Buffer size
        if !params.has_types([ValueInput, MemrefInput, MemrefOutput, None]) {
            return Err(TeeResult::BadParameters);
        }

        let (key_size_u64, svn_key_stack_size_u64) = params
            .get_values(0)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let key_size: usize = key_size_u64.trunc();
        let svn_key_stack_size =
            u32::try_from(svn_key_stack_size_u64).map_err(|_| TeeResult::BadParameters)?;

        let (extra_data_addr, extra_data_size_u64) = params
            .get_values(1)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let extra_data_size: usize = extra_data_size_u64.trunc();

        let (key_stack_addr, key_stack_buffer_size_u64) = params
            .get_values(2)
            .map_err(|_| TeeResult::BadParameters)?
            .ok_or(TeeResult::BadParameters)?;
        let key_stack_buffer_size: usize = key_stack_buffer_size_u64.trunc();

        if !(TA_DERIVED_KEY_MIN_SIZE..=TA_DERIVED_KEY_MAX_SIZE).contains(&key_size)
            || extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE
            || svn_key_stack_size > SVN_KEY_STACK_MAX_SIZE
            || svn_key_stack_size == 0
            || (extra_data_size > 0 && extra_data_addr == 0)
            || key_stack_addr == 0
        {
            return Err(TeeResult::BadParameters);
        }

        let ta_svn = self.ta_svn;
        let required_stack_buffer_size = key_size
            .checked_mul(ta_svn as usize + 1)
            .ok_or(TeeResult::BadParameters)?;
        if key_stack_buffer_size < required_stack_buffer_size {
            return Err(TeeResult::BadParameters);
        }

        let extra_data = if extra_data_size == 0 {
            Vec::new().into_boxed_slice()
        } else {
            let extra_data_ptr = UserConstPtr::<u8>::from_usize(extra_data_addr.trunc());
            extra_data_ptr
                .to_owned_slice(extra_data_size)
                .ok_or(TeeResult::BadParameters)?
        };

        // Unlike OP-TEE OS, `UserMutPtr` (and `UserConstPtr`) in LiteBox ensure this
        // pointer can never be used to access normal-world memory. That is, we don't
        // need extra security check for detecting key leakage here.
        let key_stack_ptr = UserMutPtr::<u8>::from_usize(key_stack_addr.trunc());

        // First stage: derive base key = KDF(huk, usage || ta_uuid || extra data)
        let uuid_bytes = self.ta_app_id.to_le_bytes();
        let mut stage_key = Zeroizing::new(vec![0u8; key_size]);
        self.huk_subkey_derive(
            HukSubkeyUsage::UniqueTa,
            &[&uuid_bytes, &extra_data],
            &mut stage_key,
        )?;

        // Derive keys from max SVN down to 0
        for svn_idx in (0..svn_key_stack_size).rev() {
            // Second stage KDF: HMAC(current_key, SVN_index)
            // Key_v2047 = KDF(KDF(HUK, UUID), 2047)
            // Key_v2046 = KDF(Key_v2047, 2046)
            // ...
            // Key_v001 = KDF(Key_v002, 001)
            // Key_v000 = KDF(Key_v001, 000)
            let mut hmac =
                HmacSha256::new_from_slice(&stage_key).map_err(|_| TeeResult::BadParameters)?;
            hmac.update(&svn_idx.to_le_bytes());

            let mut hmac_bytes = hmac.finalize().into_bytes();
            let derived_key = &hmac_bytes[..key_size];

            // Only copy keys for SVN values <= current TA version to userspace
            if svn_idx <= ta_svn {
                let offset = svn_idx as usize * key_size;
                key_stack_ptr
                    .copy_from_slice(offset, derived_key)
                    .ok_or(TeeResult::AccessDenied)?;
            }
            stage_key.copy_from_slice(derived_key);
            hmac_bytes.zeroize();
        }

        Ok(())
    }

    /// Derive a subkey using HUK and constant data.
    ///
    /// This follows the OP-TEE `huk_subkey_derive` interface from `core/kernel/huk_subkey.c`.
    fn huk_subkey_derive(
        &self,
        usage: HukSubkeyUsage,
        const_data: &[&[u8]],
        subkey: &mut [u8],
    ) -> Result<(), TeeResult> {
        let subkey_len = subkey.len();
        if subkey_len > HUK_SUBKEY_MAX_LEN {
            return Err(TeeResult::BadParameters);
        }

        let kdf_context_len =
            core::mem::size_of::<u32>() + const_data.iter().map(|chunk| chunk.len()).sum::<usize>();
        let mut kdf_context = Zeroizing::new(Vec::with_capacity(kdf_context_len));
        kdf_context.extend_from_slice(&(usage as u32).to_le_bytes());
        for chunk in const_data {
            kdf_context.extend_from_slice(chunk);
        }
        let kdf_params = KDFParams {
            context: kdf_context.as_slice(),
            output: subkey,
        };

        self.global
            .platform
            .derive_key(Some(huk_subkey_derive_inner), kdf_params)
            .map_err(|err| match err {
                DerivedKeyError::ShimKDFRequired
                | DerivedKeyError::UnsupportedRebootPersistentKey => TeeResult::NotSupported,
                DerivedKeyError::ShimKDFError(err) => err,
            })?;

        Ok(())
    }
}

/// A KDF callback that derives a subkey from `huk` and `params.context` to be passed to
/// the underlying platform implementation of `derive_key`.
fn huk_subkey_derive_inner(huk: &[u8], params: KDFParams<'_>) -> Result<(), TeeResult> {
    let subkey_len = params.output.len();
    if subkey_len > HUK_SUBKEY_MAX_LEN {
        return Err(TeeResult::BadParameters);
    }

    let mut hmac_bytes = HmacSha256::new_from_slice(huk)
        .map_err(|_| TeeResult::BadParameters)?
        .chain_update(params.context)
        .finalize()
        .into_bytes();
    params.output.copy_from_slice(&hmac_bytes[..subkey_len]);
    hmac_bytes.zeroize();
    Ok(())
}
