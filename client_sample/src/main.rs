//! Example hook client that demonstrates basic usage of the interceptor crate to hook functions.

#[cfg(target_arch = "x86_64")]
use core::arch::global_asm;

use interceptor::{HookType, Interceptor};
use std::ffi::{CStr, CString};
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
use windows::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};
use windows::Win32::System::SystemInformation::GetVersion;

type FuncPtr = usize;

#[cfg(target_arch = "x86_64")]
extern "system" {
    pub fn generic_hook_with_state_asm();
}

fn main() {
    // We'll hook GetVersion from kernelbase.dll
    let get_version_function_name = CString::new("GetVersion").unwrap();
    let kernelbase_module_name = CString::new("kernelbase.dll").unwrap();
    // To ensure our inline hook can be applied, we modify the protection of the target function
    // to be writable.
    let get_version_address =
        unsafe { unprotect_function(&get_version_function_name, &kernelbase_module_name) }.unwrap();

    // Log the original address
    println!("GetVersion original address: {:#x}", get_version_address);

    // Create an Interceptor to manage our hooks
    let mut interceptor = Interceptor::new();
    // Inline hook for GetVersion to our generic_hook function
    unsafe {
        // Call getversion unhooked and print the returned original result
        let version_original = GetVersion();
        println!("Original GetVersion: {:#x}", version_original);
        println!("Hook handler: {:#x}", get_version_hook as usize);
        // Start with an inline redirect (jmp) hook to our get_version_hook function, this function
        // is intended to only hook GetVersion and return a custom value.
        let hook_type = HookType::InlineRedirect(get_version_address, get_version_hook as usize);
        // Apply the hook
        interceptor.hook(hook_type).unwrap();
        // Call GetVersion() again, this time it should be hooked and we should obtain the custom
        // value returned by get_version_hook
        let version_hooked = GetVersion();
        // Print the custom value
        println!("Hooked GetVersion: {:#x}", version_hooked);
        // unhook GetVersion
        interceptor.unhook(get_version_address).unwrap();
        // Call GetVersion() again, this time it should be unhooked and we should obtain the original
        // value returned by GetVersion
        let version_original2 = GetVersion();
        println!("Original (2) GetVersion: {:#x}", version_original2);
    }

    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Hook GetVersion again, this time with a generic x64 hook that can be used to hook
        // almost any function and provides read/write access to the register state at time of
        // call.
        let hook_type =
            HookType::InlineRedirect(get_version_address, generic_hook_with_state_asm as usize);
        println!("Hook handler: {:#x}", generic_hook_with_state_asm as usize);
        interceptor.hook(hook_type).unwrap();

        // To test intercepting register state, we'll modify GetVersion function definition
        // to take 4 arguments (on x64, this'll be placed in rcx, rdx, r8, r9). This allows
        // us to dump the intercepted register state in our hook and verify rcx contains
        // 0xdeadbeef, rdx contains 0x1337, r8 contains 0x12345678, and r9 contains 0x87654321.
        let get_version_fn: extern "system" fn(usize, usize, usize, usize) -> usize =
            std::mem::transmute(get_version_address);

        let arg1 = 0xdeadbeef;
        let arg2 = 0x1337;
        let arg3 = 0x12345678;
        let arg4 = 0x87654321;
        println!(
            "Calling function with args: {:#x} {:#x} {:#x} {:#x}",
            arg1, arg2, arg3, arg4
        );
        // Call GetVersion, which should be intercepted into our hook
        let result = get_version_fn(arg1, arg2, arg3, arg4);
        // Our hook will modify the `rax` register, this corresponds to the return value register
        // on x64 system targets. Print the result which should show our custom value.
        println!("Result: {:#x}", result);
        // unhook
        interceptor.unhook(get_version_address).unwrap();
    }
    println!("Done");
}

/// Unprotects a function in a module to allow for inline hooking.
unsafe fn unprotect_function(function_name: &CStr, module_name: &CStr) -> Option<FuncPtr> {
    let module_handle =
        GetModuleHandleA(PCSTR::from_raw(module_name.as_ptr() as *const u8)).ok()?;
    let function_address = GetProcAddress(
        module_handle,
        PCSTR::from_raw(function_name.as_ptr() as *const u8),
    )?;

    // yolo rwx
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        function_address as _,
        20,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )
    .ok()?;

    Some(function_address as usize)
}

#[cfg(target_arch = "x86_64")]
#[no_mangle]
/// Generic hook that can be used to hook almost any function and provides read/write access to the
/// register state at time of call.
pub extern "system" fn generic_hook_with_state(regs: &mut RegisterState) {
    println!("generic_hook_with_state called! Registers: {:#x?}", regs);
    // Modify the rax register (typically the return value register on x64) to return a custom value
    // for fun.
    regs.rax = 0xdeadbeef;
}

/// Hook handler for GetVersion that returns a custom version.
pub extern "system" fn get_version_hook() -> u32 {
    println!("get_version_hook called!");
    // Return custom version
    0x1337
}

#[cfg(target_arch = "x86_64")]
#[repr(C, packed(1))]
#[derive(Debug)]
pub struct RegisterState {
    rflags: u64,
    xmm15: u128,
    xmm14: u128,
    xmm13: u128,
    xmm12: u128,
    xmm11: u128,
    xmm10: u128,
    xmm9: u128,
    xmm8: u128,
    xmm7: u128,
    xmm6: u128,
    xmm5: u128,
    xmm4: u128,
    xmm3: u128,
    xmm2: u128,
    xmm1: u128,
    xmm0: u128,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rsp: u64,
}

#[cfg(target_arch = "x86_64")]
// Generic hook handler that backs up general purpose registers and XMM registers, then calls
// a generic hook function with a pointer to the RegisterState struct on the stack that can be
// modified by the hook function, then we load the potentially modified registers and return.
global_asm!(
    r#"
    .global generic_hook_with_state_asm
    generic_hook_with_state_asm:
        push rsp
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rdi
        push rsi
        push rbp
        push rbx
        push rdx
        push rcx
        push rax
        sub rsp, 16
        movdqu [rsp], xmm0
        sub rsp, 16
        movdqu [rsp], xmm1
        sub rsp, 16
        movdqu [rsp], xmm2
        sub rsp, 16
        movdqu [rsp], xmm3
        sub rsp, 16
        movdqu [rsp], xmm4
        sub rsp, 16
        movdqu [rsp], xmm5
        sub rsp, 16
        movdqu [rsp], xmm6
        sub rsp, 16
        movdqu [rsp], xmm7
        sub rsp, 16
        movdqu [rsp], xmm8
        sub rsp, 16
        movdqu [rsp], xmm9
        sub rsp, 16
        movdqu [rsp], xmm10
        sub rsp, 16
        movdqu [rsp], xmm11
        sub rsp, 16
        movdqu [rsp], xmm12
        sub rsp, 16
        movdqu [rsp], xmm13
        sub rsp, 16
        movdqu [rsp], xmm14
        sub rsp, 16
        movdqu [rsp], xmm15
        pushfq
        # move pointer to the the X64RegisterState struct into rcx
        lea rcx, [rsp]
        call generic_hook_with_state
        popfq
        movdqu  xmm15, [rsp]
        add     rsp, 16
        movdqu  xmm14, [rsp]
        add     rsp, 16
        movdqu  xmm13, [rsp]
        add     rsp, 16
        movdqu  xmm12, [rsp]
        add     rsp, 16
        movdqu  xmm11, [rsp]
        add     rsp, 16
        movdqu  xmm10, [rsp]
        add     rsp, 16
        movdqu  xmm9, [rsp]
        add     rsp, 16
        movdqu  xmm8, [rsp]
        add     rsp, 16
        movdqu  xmm7, [rsp]
        add     rsp, 16
        movdqu  xmm6, [rsp]
        add     rsp, 16
        movdqu  xmm5, [rsp]
        add     rsp, 16
        movdqu  xmm4, [rsp]
        add     rsp, 16
        movdqu  xmm3, [rsp]
        add     rsp, 16
        movdqu  xmm2, [rsp]
        add     rsp, 16
        movdqu  xmm1, [rsp]
        add     rsp, 16
        movdqu  xmm0, [rsp]
        add     rsp, 16
        pop rax
        pop rcx
        pop rdx
        pop rbx
        pop rbp
        pop rsi
        pop rdi
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
        pop rsp
        ret
    "#,
);
