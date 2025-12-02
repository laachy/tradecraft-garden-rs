#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::ptr::null_mut;
use crystal_palace_rs::{append_data, import};
use crystal_palace_sys::tcg::{IMPORTFUNCS, PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoLoad, findFunctionByHash, findModuleByHash};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

append_data!(my_data, findAppendedPICO);

#[unsafe(no_mangle)]
extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe {
        let dst_code;
        let dst_data;
        let src = findAppendedPICO();     /* find our PICO appended to this PIC */
        let mut funcs = IMPORTFUNCS { 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };

        /* allocate memory for our PICO */
        dst_code = VirtualAlloc(null_mut(), PicoCodeSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
        dst_data = VirtualAlloc(null_mut(), PicoDataSize(src as _) as _, MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN, PAGE_READWRITE);
        
        /* load our pico into our destination address, thanks! */
        PicoLoad(&mut funcs, src as _, dst_code as _, dst_data as _);

        /* execute our pico */
        PicoEntryPoint(src as _, dst_code as _).unwrap_unchecked()(null_mut());
    }
}