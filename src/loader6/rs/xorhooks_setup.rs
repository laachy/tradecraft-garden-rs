#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{ffi::{self, c_void}, mem};

use crystal_palace_sys::tcg::{DLLDATA, PicoGetExport, SizeOfDLL};
use winapi::shared::minwindef::DWORD;

type PicoConfigHooks = unsafe extern "C" fn(dll_base: *const u8, dll_sz: DWORD);
unsafe extern "C" { 
    /*
     * tradecraft modules in this architecture are responsible for kicking off the init chain and they're
     * responsible for providing a getStart() function to make the beginning of our PIC findable
     */
    fn init(); 

    /* this is a linker intrinsic to get the tag of our confighooks export function. */
    fn __tag_confighooks() -> ffi::c_int;
}

/*
 * setupHooks is called by the loader to allow our tradecraft to work with the DLL hooking BOF.
 * This is our chance to grab an exported function and pass our configuration on.
 */
#[unsafe(no_mangle)]
extern "C" fn setupHooks(src_hooks: *const u8, dst_hooks: *const u8, data: *const DLLDATA, dst_dll: *const u8) {
    unsafe { 
        mem::transmute::<_, PicoConfigHooks>(PicoGetExport(src_hooks as _, dst_hooks as _, __tag_confighooks()).unwrap_unchecked())(
            dst_dll, SizeOfDLL(data as _)
        );
    }
}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { init() };
}

#[unsafe(no_mangle)]
extern "C" fn getStart() -> *const c_void{
    go as _
}