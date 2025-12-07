#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::null_mut};
use crystal_sdk::{append_data, import};
use crystal_bindings::tcg::{DLLDATA, EntryPoint, IMPORTFUNCS, LoadDLL, ParseDLL, ProcessImports, SizeOfDLL};
use winapi::{shared::{minwindef::{DWORD, FARPROC, HMODULE, LPVOID}, ntdef::LPCSTR}, um::winnt::{DLL_PROCESS_ATTACH, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE}};

#[unsafe(no_mangle)]
pub extern "C" fn resolve(module: *const i8, function: *const i8) -> FARPROC {
    unsafe {
        let h_module = mem::transmute::<_, GetModuleHandleAFn>(pGetModuleHandle)(module);
        mem::transmute::<_, GetProcAddressFn>(pGetProcAddress)(h_module, function as _)
    }
}

type GetModuleHandleAFn = unsafe extern "system" fn(lp_module_name: *const i8) -> HMODULE;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static mut pGetModuleHandle: usize = 1;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
static mut pGetProcAddress: usize = 1;

append_data!(my_data, findAppendedDLL);

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe { 
        let src = findAppendedDLL();    /* find our DLL appended to this PIC */
        let dst;
        let mut data: DLLDATA = mem::zeroed();

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
        EntryPoint(&mut data, dst as _).unwrap_unchecked()(
            dst as _, DLL_PROCESS_ATTACH, null_mut()
        );
    };
}
