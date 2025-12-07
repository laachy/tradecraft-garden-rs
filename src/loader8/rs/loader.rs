#![no_std]
#![no_main]

use core::{mem, ptr::null_mut};
use crystal_sdk::{append_data, import};
use crystal_bindings::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, PicoCodeSize, PicoDataSize, PicoEntryPoint, PicoLoad, ProcessImports, SizeOfDLL, findFunctionByHash, findModuleByHash};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

append_data!(my_data, findAppendedCapability);

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

/*
 * Where is go()?
 *
 * Notice that we haven't defined a go() entrypoint here. Instead, we have two candidate entry
 * points. One for a PICO and one for a DLL. The link.spec file will remap go_dll or go_object to
 * go() at link-time, based on whether a DLL or COFF is presented. This allows us to build one
 * program to handle either a DLL or COFF capability. Crystal Palace's link-time optimization
 * will remove the unused entry point candidate.
 */

#[unsafe(no_mangle)]
extern "C" fn go_object() {
    unsafe { 
        let src = findAppendedCapability();    /* find our COFF appended to this PIC */
        let dst_code;
        let dst_data;
        let mut funcs = IMPORTFUNCS{ 
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
    };
}

#[unsafe(no_mangle)]
extern "C" fn go_dll() {
    unsafe { 
        let src = findAppendedCapability();    /* find our DLL appended to this PIC */
        let dst;
        let mut data: DLLDATA = mem::zeroed();
        let mut funcs = IMPORTFUNCS{ 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };

        /* allocate memory for it! */
        ParseDLL(src as _, &mut data);

        /* allocate memory for it! */
        dst = VirtualAlloc(null_mut(), SizeOfDLL(&mut data) as _, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        /* load the damned thing */
        LoadDLL(&mut data, src as _, dst as _);

        /* process the imports */
        ProcessImports(&mut funcs, &mut data, dst as _);

        /* excute it! */
        EntryPoint(&mut data, dst as _).unwrap_unchecked()(dst as _, DLL_PROCESS_ATTACH, null_mut());
    };
}
