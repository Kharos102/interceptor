//! Example library for hooking functions on x86 and x86-64 architectures.
//! Platform-agnostic, but requires the `alloc` crate.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::SeqCst;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8};

#[cfg(target_arch = "x86")]
use alloc::boxed::Box;
#[cfg(target_arch = "x86")]
use core::pin::Pin;

/// Pointer to the address containing the target pointer we will hook / replace.
/// E.g. if `0x13371337` (dubbed pointer A) is a pointer to a function we want to hook, and `0x13381338`
/// (dubbed pointer B) is a pointer to pointer A, then this `PointerToTargetAddress` would contain address of pointer B,
/// which would be `0x13381338`. This is useful when hooking IAT entries, where the IAT entry is a pointer to the address
/// of the function we want to hook.
pub type PointerToTargetAddress = *mut usize;

/// Atomic version of the pointer to the address that will be hooked,
/// used for atomic operations
type AtomicPointerToTargetAddress<'a> = &'a AtomicPtr<usize>;

/// Target address we want to inline hook, e.g. if `0x13371337` is the address of a function we want to hook,
/// then this `TargetAddress` would be `0x13371337`.
pub type TargetAddress = usize;

/// Address of the function that will handle the hook.
pub type HookHandlerAddress = usize;

/// Request for creating a hook based on switching pointers (e.g. as in IAT hooking).
pub struct PointerHook<'a> {
    original_address_ptr: AtomicPointerToTargetAddress<'a>,
    original_address: usize,
    new_address: usize,
}

impl PointerHook<'_> {
    /// Unhook the function by swapping the original address back into the original address pointer.
    /// Returns an error if the current address in the target does not match our hook handler address
    /// (indicating our hook was overwritten).
    fn unhook(&mut self) -> Result<(), InterceptorError> {
        self.original_address_ptr
            .compare_exchange(
                &mut self.new_address,
                &mut self.original_address,
                SeqCst,
                SeqCst,
            )
            .map_err(|e| InterceptorError::HookedAddressUnexpected(e as *mut _ as usize))
            .map(|_| ())
    }

    /// Get the original address that was hooked.
    fn _get_hooked_address(&self) -> usize {
        self.original_address
    }
    /// Get the address of the function that will handle the hook.
    fn _get_hook_handler_address(&self) -> usize {
        self.new_address
    }
    /// Apply the hook by swapping the original address with the new address.
    /// Returns a new `PointerHook` instance to track and manage the hook.
    unsafe fn hook(
        original_address_ptr: PointerToTargetAddress,
        new_address: HookHandlerAddress,
    ) -> Self {
        // Perform an atomic swap on the original address
        let mut new_address_tmp = new_address;
        let atomic_original_address_ptr = AtomicPtr::from_ptr(original_address_ptr as *mut *mut _);
        let original_address =
            atomic_original_address_ptr.swap(&mut new_address_tmp, SeqCst) as *mut _ as usize;
        Self {
            original_address_ptr: atomic_original_address_ptr,
            original_address,
            new_address,
        }
    }
}

/// Request for creating a hook based on inline redirection.
/// This method replaces bytes in the target address with a jump to the hook handler address.
/// Upon unhooking, it restores the original bytes.
pub struct InlineHook {
    target_address: TargetAddress,
    _hook_handler_address: HookHandlerAddress,
    original_bytes: Vec<u8>,
    new_bytes: Vec<u8>,
    #[cfg(target_arch = "x86")]
    jmp_buffer: Pin<Box<[u8; 4]>>,
    #[cfg(target_arch = "x86")]
    _phantom_pinned: core::marker::PhantomPinned,
}

impl InlineHook {
    /// Attempt to unhook the function by restoring the original bytes.
    /// Returns an error if the current bytes in the target address do not match our new bytes (indicating our hook was overwritten).
    fn unhook(&mut self) -> Result<(), InterceptorError> {
        // Check that our hook hasn't been overwritten
        let current_bytes = try_read_atomic(ReadRequest {
            target_address: self.target_address as *mut u8,
            len_to_read: self.new_bytes.len() as u64,
        });
        if current_bytes != self.new_bytes {
            return Err(InterceptorError::HookedAddressUnexpected(
                self.target_address,
            ));
        }
        // Create a request for try_write_atomic
        let req = WriteRequest {
            target_address: self.target_address as *mut u8,
            bytes_to_write: self.original_bytes.clone(),
        };
        try_write_atomic(req);

        Ok(())
    }
    /// Get the original address that was hooked.
    fn _get_hooked_address(&self) -> usize {
        self.target_address
    }
    /// Get the address of the function that will handle the hook.
    fn _get_hook_handler_address(&self) -> usize {
        self._hook_handler_address
    }

    /// Apply the hook by replacing the target address bytes with a jump to the hook handler address.
    /// Safety: The target address must be a valid address that can be read and written to.
    unsafe fn hook(address_to_patch: TargetAddress, new_address: HookHandlerAddress) -> Self {
        // Create a jump to the new address
        let mut self_tmp = Self {
            target_address: address_to_patch,
            _hook_handler_address: new_address,
            original_bytes: vec![],
            new_bytes: vec![],
            #[cfg(target_arch = "x86")]
            jmp_buffer: Box::pin([0; 4]),
            #[cfg(target_arch = "x86")]
            _phantom_pinned: core::marker::PhantomPinned,
        };
        let jmp = self_tmp.create_jmp(new_address);
        let original_bytes = try_read_atomic(ReadRequest {
            target_address: address_to_patch as *mut u8,
            len_to_read: jmp.len() as u64,
        });
        let req = WriteRequest {
            target_address: address_to_patch as *mut u8,
            bytes_to_write: jmp.clone(),
        };
        try_write_atomic(req);
        self_tmp.original_bytes = original_bytes;
        self_tmp.new_bytes = jmp;

        self_tmp
    }

    #[cfg(target_arch = "x86_64")]
    fn create_jmp(&mut self, target: usize) -> Vec<u8> {
        // Create an absolute indirect jmp
        let mut jmp: Vec<u8> = vec![0x48, 0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
        jmp.extend_from_slice(&(target as u64).to_le_bytes());
        // If the jmp length is less than 8 but not 1, 2 or 4, pad with nops to support
        // atomic operations that operate on buffer lengths of 1, 2, 4 or 8
        let jmp_len = jmp.len();
        if jmp_len > 2 && jmp_len < 4 {
            let pad_length = 4 - jmp_len;
            for _ in 0..pad_length {
                jmp.push(0x90);
            }
            jmp
        } else if jmp_len > 4 && jmp_len < 8 {
            let pad_length = 8 - jmp_len;
            for _ in 0..pad_length {
                jmp.push(0x90);
            }
            jmp
        } else {
            jmp
        }
    }

    #[cfg(target_arch = "x86")]
    fn create_jmp(&mut self, target: usize) -> Vec<u8> {
        // Create an absolute indirect jmp
        self.jmp_buffer = Box::pin((target as u32).to_le_bytes());
        let mut jmp: Vec<u8> = vec![0xff, 0x25];
        jmp.extend_from_slice(&(self.jmp_buffer.as_ptr() as u32).to_le_bytes());
        // If the jmp length is less than 8 but not 1, 2 or 4, pad with nops to support
        // atomic operations that operate on buffer lengths of 1, 2 or 4
        let jmp_len = jmp.len();
        if jmp_len > 2 && jmp_len < 4 {
            let pad_length = 4 - jmp_len;
            for _ in 0..pad_length {
                jmp.push(0x90);
            }
            jmp
        } else {
            jmp
        }
    }
}

/// Error type for the Interceptor
#[derive(Debug)]
pub enum InterceptorError {
    HookedAddressUnexpected(usize),
    HookNotFound,
    HookAlreadyExists,
}

/// The type of hook to apply.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum HookType {
    FunctionPtr(PointerToTargetAddress, HookHandlerAddress),
    InlineRedirect(TargetAddress, HookHandlerAddress),
}

/// The Interceptor struct is used to manage hooks
pub struct Interceptor<'a> {
    inline_hooks: Vec<InlineHook>,
    pointer_hooks: Vec<PointerHook<'a>>,
}

impl Interceptor<'_> {
    pub fn new() -> Self {
        Self {
            inline_hooks: Vec::new(),
            pointer_hooks: Vec::new(),
        }
    }
    /// Apply a hook.
    /// Safety: Any provided target address must be a valid address that can be read and written to.
    pub unsafe fn hook(&mut self, hook_type: HookType) -> Result<(), InterceptorError> {
        match hook_type {
            HookType::FunctionPtr(original_address_ptr, new_address) => {
                if self.pointer_hooks.iter().any(|h| {
                    h.original_address_ptr.as_ptr() == original_address_ptr as *mut *mut usize
                }) {
                    return Err(InterceptorError::HookAlreadyExists);
                }
                let hook = PointerHook::hook(original_address_ptr, new_address);

                self.pointer_hooks.push(hook);
                Ok(())
            }
            HookType::InlineRedirect(target_address, hook_handler_address) => {
                if self
                    .inline_hooks
                    .iter()
                    .any(|h| h.target_address == target_address)
                {
                    return Err(InterceptorError::HookAlreadyExists);
                }
                let hook = InlineHook::hook(target_address, hook_handler_address);
                self.inline_hooks.push(hook);
                Ok(())
            }
        }
    }

    /// Unhook a function.
    /// Safety: The provided address must be a valid address that can be read and written to.
    pub fn unhook(&mut self, original_address: usize) -> Result<(), InterceptorError> {
        // Search for the hook in both the inline and pointer hooks, if found unhook it
        // and pop it from the vector
        if let Some(hook) = self
            .inline_hooks
            .iter()
            .position(|h| h.target_address == original_address)
        {
            self.inline_hooks[hook].unhook()?;
            self.inline_hooks.remove(hook);
            Ok(())
        } else if let Some(hook) = self
            .pointer_hooks
            .iter()
            .position(|h| h.original_address == original_address)
        {
            self.pointer_hooks[hook].unhook()?;
            self.pointer_hooks.remove(hook);
            Ok(())
        } else {
            Err(InterceptorError::HookNotFound)
        }
    }
}

/// Request to write bytes to a target address.
struct WriteRequest {
    target_address: *mut u8,
    bytes_to_write: Vec<u8>,
}

/// Request to read bytes from a target address.
struct ReadRequest {
    target_address: *mut u8,
    len_to_read: u64,
}

/// Attempt to read bytes from a target address.
/// Uses atomic operations if the size of the bytes to read is 1-8 bytes, otherwise uses a memcpy.
fn try_read_atomic(req: ReadRequest) -> Vec<u8> {
    // If the size of the bytes to read is 1-8 bytes, use the associated
    // atomics, otherwise use a memcpy
    match req.len_to_read {
        1 => {
            let target_address = unsafe { AtomicU8::from_ptr(req.target_address) };
            vec![target_address.load(SeqCst)]
        }
        2 => {
            let target_address = unsafe { AtomicU16::from_ptr(req.target_address as *mut u16) };
            let bytes = target_address.load(SeqCst);
            unsafe { core::mem::transmute::<u16, [u8; 2]>(bytes) }.to_vec()
        }
        4 => {
            let target_address = unsafe { AtomicU32::from_ptr(req.target_address as *mut u32) };
            let bytes = target_address.load(SeqCst);
            unsafe { core::mem::transmute::<u32, [u8; 4]>(bytes) }.to_vec()
        }
        8 => {
            let target_address = unsafe { AtomicU64::from_ptr(req.target_address as *mut u64) };
            let bytes = target_address.load(SeqCst);
            unsafe { core::mem::transmute::<u64, [u8; 8]>(bytes) }.to_vec()
        }
        _ => {
            // Do a memcpy based on the size of the original bytes
            let mut bytes = Vec::with_capacity(req.len_to_read as usize);
            for i in 0..req.len_to_read {
                let target_address: *mut u8 = (req.target_address as usize + i as usize) as *mut u8;

                bytes.push(unsafe { target_address.read() });
            }
            bytes
        }
    }
}

/// Attempt to write bytes to a target address.
/// Uses atomic operations if the size of the bytes to write is 1-8 bytes, otherwise uses a memcpy.
fn try_write_atomic(req: WriteRequest) {
    // If the size of the bytes to write is 1-8 bytes, use the associated
    // atomics, otherwise use a memcpy
    match req.bytes_to_write.len() {
        1 => {
            let target_address = unsafe { AtomicU8::from_ptr(req.target_address) };
            target_address.store(req.bytes_to_write[0], SeqCst);
        }
        2 => {
            let bytes = unsafe {
                core::mem::transmute::<[u8; 2], u16>([req.bytes_to_write[0], req.bytes_to_write[1]])
            };
            let target_address = unsafe { AtomicU16::from_ptr(req.target_address as *mut u16) };
            target_address.store(bytes, SeqCst);
        }
        4 => {
            let bytes = unsafe {
                core::mem::transmute::<[u8; 4], u32>([
                    req.bytes_to_write[0],
                    req.bytes_to_write[1],
                    req.bytes_to_write[2],
                    req.bytes_to_write[3],
                ])
            };
            let target_address = unsafe { AtomicU32::from_ptr(req.target_address as *mut u32) };
            target_address.store(bytes, SeqCst);
        }
        8 => {
            let bytes = unsafe {
                core::mem::transmute::<[u8; 8], u64>([
                    req.bytes_to_write[0],
                    req.bytes_to_write[1],
                    req.bytes_to_write[2],
                    req.bytes_to_write[3],
                    req.bytes_to_write[4],
                    req.bytes_to_write[5],
                    req.bytes_to_write[6],
                    req.bytes_to_write[7],
                ])
            };
            let target_address = unsafe { AtomicU64::from_ptr(req.target_address as *mut u64) };
            target_address.store(bytes, SeqCst);
        }
        _ => {
            // Do a memcpy based on the size of the original bytes
            for (i, byte) in req.bytes_to_write.iter().enumerate() {
                let target_address: *mut u8 = (req.target_address as usize + i) as *mut u8;

                unsafe {
                    target_address.write(*byte);
                }
            }
        }
    }
}
