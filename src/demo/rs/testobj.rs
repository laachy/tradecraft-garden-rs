#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::ptr::null_mut;

use crystal_palace_rs::import;
use winapi::shared::{minwindef::UINT, ntdef::LPCSTR, windef::HWND};

import!(USER32!MessageBoxA(hWnd: HWND, lpText: LPCSTR, lpCaption: LPCSTR, uType: UINT) -> i32);

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { MessageBoxA(null_mut(), c"Hello World (COFF)".as_ptr() as _, c"Test!".as_ptr() as _, 0) };
}