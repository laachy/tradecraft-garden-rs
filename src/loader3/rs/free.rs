#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::null_mut};
use crystal_sdk::import;
use crystal_bindings::tcg::DLLMAIN_FUNC;
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, LPVOID}}, um::winnt::{DLL_PROCESS_ATTACH, MEM_RELEASE}};

import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(KERNEL32!ExitThread(dwExitCode: DWORD) -> !);

#[unsafe(no_mangle)]
extern "C" fn go(loader: *mut u8, dll_entry: *const u8, dll_base: *const u8) {
    unsafe {
        VirtualFree(loader as _, 0, MEM_RELEASE);

        mem::transmute::<_, DLLMAIN_FUNC>(dll_entry).unwrap_unchecked()(
            dll_base as _, DLL_PROCESS_ATTACH, null_mut()
        );

        ExitThread(0);
    }
}
