#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::null_mut};
use crystal_palace_rs::import;
use crystal_palace_sys::tcg::DLLMAIN_FUNC;
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, LPVOID}}, um::winnt::{DLL_PROCESS_ATTACH, MEM_RELEASE}};

import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(KERNEL32!ExitThread(dwExitCode: DWORD) -> !);

#[unsafe(no_mangle)]
extern "C" fn freeAndRun(loader: *mut u8, dll_entry: *const u8, dll_base: *const u8) {
    unsafe {
        /* free our loader */
        VirtualFree(loader as _, 0, MEM_RELEASE);

        /* call the entry point of our Reflective DLL */
        mem::transmute::<_, DLLMAIN_FUNC>(dll_entry).unwrap_unchecked()(
            dll_base as _, DLL_PROCESS_ATTACH, null_mut()
        );

        /* exit the current thread.. else... we return to our free'd() memory and we don't want that. */
        ExitThread(0);
    }
}
