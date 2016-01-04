

#[cfg(windows)]
extern crate ws2_32;

use std::mem;

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
pub fn other_init() {
}
