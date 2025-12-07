#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::{ffi::{self}, mem};
use crystal_bindings::tcg::{PicoGetExport, SizeOfDLL, DLLDATA};
use winapi::shared::minwindef::DWORD;

type PicoConfigHooks = unsafe extern "C" fn(dll_base: *const u8, dll_sz: DWORD);

unsafe extern "C" {
    /* this is a linker intrinsic to get the tag of our confighooks export function. */
    fn __tag_confighooksXor() -> ffi::c_int;

    /*
     * setupHooks is called by the loader to allow our tradecraft to work with the DLL hooking BOF.
     * This is our chance to grab an exported function and pass our configuration on.
     */
    fn setupHooks(src_hooks: *const u8, dst_hooks: *const u8, data: *const DLLDATA, dst_dll: *const u8);
}

/*
 * setupHooks is called by the loader to allow our tradecraft to work with the DLL hooking BOF.
 * This is our chance to grab an exported function and pass our configuration on.
 */
#[unsafe(no_mangle)]
extern "C" fn setupHooksXor(src_hooks: *const u8, dst_hooks: *const u8, data: *const DLLDATA, dst_dll: *const u8) {
    unsafe {
        /* call the configuration function exported by our PICO */
        mem::transmute::<_, PicoConfigHooks>(
            PicoGetExport(src_hooks as _, dst_hooks as _, __tag_confighooksXor())
                .unwrap_unchecked(),
        )(dst_dll, SizeOfDLL(data as _));

        /* continue the chain */
        setupHooks(src_hooks, dst_hooks, data, dst_dll);

        // stop TCO
        core::arch::asm!("", options(nomem, nostack, preserves_flags));
    }
}
