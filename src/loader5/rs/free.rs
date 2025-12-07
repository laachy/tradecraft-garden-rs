#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use crystal_sdk::import;
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, LPVOID},},um::winnt::{MEM_RELEASE}};

import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(KERNEL32!ExitThread(dwExitCode: DWORD) -> !);

core::arch::global_asm!(
    r#"
    .def go_stage2;
    .scl 2;
    .type 32;
    .endef
"#
);

unsafe extern "C" {
    fn go_stage2();
}

#[unsafe(no_mangle)]
extern "C" fn go(loader: *mut u8, _dll_entry: *const u8, _dll_base: *const u8) {
    unsafe {
        /* free our loader */
        VirtualFree(loader as _, 0, MEM_RELEASE);

        /* call the entry point of our capability */
        go_stage2();

        /* exit the current thread.. else... we return to our free'd() memory and we don't want that. */
        ExitThread(0);
    }
}
