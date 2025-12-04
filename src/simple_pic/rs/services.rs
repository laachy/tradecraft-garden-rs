#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::{null, null_mut}};
use crystal_sdk::{import};
use crystal_bindings::tcg::{DLLDATA, ParseDLL, findFunctionByHash, findModuleByHash};
use winapi::{shared::{minwindef::{FARPROC, HMODULE}, ntdef::LPCSTR}, um::winnt::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER}};



import!(KERNEL32!GetModuleHandleA(lpModuleName: LPCSTR) -> HMODULE);
import!(LoadLibraryA(arg1: LPCSTR) -> HMODULE);
import!(GetProcAddress(arg1: HMODULE, arg2: LPCSTR) -> FARPROC);


/*
 * This is our opt-in Dynamic Function Resolution resolver. It turns MODULE$Function into pointers.
 * See dfr "resolve" "ror13" "KERNEL32, NTDLL" in loader.spec
 */
#[unsafe(no_mangle)]
extern "C" fn resolve(mod_hash: u32, func_hash: u32) -> FARPROC {
    unsafe {
        let h_module = findModuleByHash(mod_hash);
        findFunctionByHash(h_module, func_hash)
    }
}

/*
 * This is our default DFR resolver. It resolves Win32 APIs not handled by another resolver.
 */
#[unsafe(no_mangle)]
extern "C" fn resolve_ext(module: *const i8, function: *const i8) -> FARPROC {
    unsafe {
        let mut h_module = GetModuleHandleA(module);
        if h_module.is_null() {
            h_module = LoadLibraryA(module);
        }
        GetProcAddress(h_module, function)
    }
}

fn find_data_cave(dll_base: *const u8, length: u32) -> Option<*mut u8>{
    unsafe {
        let mut data: DLLDATA = mem::zeroed();
        let mut section_hdr;
        let mut section_nxt;
        let num_of_sections;

        /* parse our DLL! */
        ParseDLL(dll_base as _, &mut data);

        /* loop through our sections */
        num_of_sections = (*data.NtHeaders).FileHeader.NumberOfSections;
        section_hdr = (data.OptionalHeader as usize + (*data.NtHeaders).FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;
        for _ in 0..num_of_sections-1 {
            /* look for our RW section! */
            const DATA_FLAGS: u32 = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
            if (*section_hdr).Characteristics & DATA_FLAGS == DATA_FLAGS {
                /* let's look at our next section, we need it to get the right size of the code cave */
                section_nxt = &*section_hdr.add(1);

                /* calculate the size, based on section headers */
                let size = section_nxt.VirtualAddress - (*section_hdr).VirtualAddress;

                /* calculate the size of our code cave */
                let cave_size = size - (*section_hdr).SizeOfRawData;

                /* if we fit, return it */
                if length < cave_size {
                    return Some((dll_base as usize + (section_nxt.VirtualAddress - cave_size) as usize) as _);
                }
                /* advance to our next section */
                section_hdr = section_hdr.add(1);
            }
        }
        None
    }
}

/*
 * This is our opt-in fixbss function. The method here is to look for slack R/W space within various
 * loaded modules and use that for our .bss section. This is not compatible with multiple PICs being
 * resident in the same process space using this method--but it does do the job of giving us global
 * variables in our PIC.
 */
#[unsafe(no_mangle)]
extern "C" fn getBSS(length: u32) -> *mut u8{
    unsafe {
        /* try in our module */
        let mut h_module = GetModuleHandleA(null());
        if let Some(ptr) = find_data_cave(h_module as _, length) {
            return ptr;
        }

        /* try in kernel32 */
        h_module = GetModuleHandleA(c"Kernel32".as_ptr()); 
        if let Some(ptr) = find_data_cave(h_module as _, length) {
            return ptr;
        }

        /* it's really bad news if we get here... ka-rash! */
        null_mut()
    }
}