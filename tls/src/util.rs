
#[cfg(windows)]
extern crate ws2_32;

#[cfg(windows)]
use std::mem;
use std::ffi::{CStr, CString};
use libc::c_char;
use std::ptr;

#[cfg(windows)]
pub fn other_init() {
    // libtls currently (2.3.1) fails to initialize the
    // windows network stack - issue #167
    unsafe {
        let mut data = mem::zeroed();
        ws2_32::WSAStartup(0x202, &mut data);
    }
}

#[cfg(not(windows))]
pub fn other_init() {}

pub fn from_cstr(s: *const c_char) -> String {
    unsafe {
        if s == ptr::null_mut() {
            String::new()
        } else {
            let slice = CStr::from_ptr(s);
            String::from_utf8_lossy(slice.to_bytes()).into_owned()
        }
    }
}

/// Get C string ptr, but use NULL if the string is empty.
/// Because some C functions treat NULL and "\0" differently
pub fn str_c_ptr(s: &str) -> *const i8 {
    if s.is_empty() {
        ptr::null()
    } else {
        unsafe { CString::from_vec_unchecked(s.bytes().collect()).as_ptr() }
    }
}
