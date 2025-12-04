#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{ffi, slice::from_raw_parts_mut};
use crystal_sdk::import;
use winapi::shared::{minwindef::{DWORD, UINT}, ntdef::LPCSTR, windef::HWND};

import!(USER32!MessageBoxA(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) -> ffi::c_int);

/*
 * our xorkey, we're going to set this via our loader.spec
 */
#[unsafe(no_mangle)]
static mut xorkey: [u8;128] = [1; 128];

/* global to keep track of our DLL in memory. For simplicity's sake, this example
 * assumes the whole thing is RWX, but we could really do whatever we need between
 * the loader and this hooking module */
static mut DLL: &mut [u8] = &mut [];

/*
 * A simple routine to obfuscate and de-obfuscate our data
 */
fn apply_xor(data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= unsafe { xorkey }[i % 128];
    }
}

/*
 * our MessageBoxA hook. See addhook "USER32$MessageBoxA" in loader.spec
 */
#[unsafe(no_mangle)]
extern "system" fn _xMessageBoxA(h_wnd: HWND, _lp_text: LPCSTR, _lp_caption: LPCSTR, u_type: UINT) -> i32{
    unsafe {
        let result;

        apply_xor(DLL);

        // may as well use our own strings, because the originals are garbled right now
        result = MessageBoxA(h_wnd, c"Hello from hook.rs".as_ptr(), c"HOOKED CUHHHH".as_ptr(), u_type);

        apply_xor(DLL);

        result
    }
}

#[unsafe(no_mangle)]
extern "C" fn confighooksXor(dll_base: *mut u8, dll_sz: DWORD) {
    /* track this information, because we will need it later */
    unsafe { DLL = from_raw_parts_mut(dll_base, dll_sz as _) };
}