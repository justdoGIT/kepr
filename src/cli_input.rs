// cli_input.rs — masked TTY input for interactive secret entry.
//
// Uses raw termios FFI (no external crate) to disable ECHO around read_line.

use std::io::{self, BufRead, Write};

use kepr_core::generate::ZeroString;

#[repr(C)]
#[derive(Clone, Copy)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 32],
    c_ispeed: u32,
    c_ospeed: u32,
}
const ECHO: u32 = 0x00000008;

extern "C" {
    fn tcgetattr(fd: i32, t: *mut Termios) -> i32;
    fn tcsetattr(fd: i32, a: i32, t: *const Termios) -> i32;
}

fn get_termios() -> Termios {
    let mut t = Termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    // SAFETY: fd 0 and a valid termios struct for the call to fill.
    unsafe {
        tcgetattr(0, &mut t);
    }
    t
}

fn set_termios(t: &Termios) {
    // SAFETY: fd 0 and a valid termios struct.
    unsafe {
        tcsetattr(0, 0, t);
    }
}

pub fn read_masked(prompt: &str) -> ZeroString {
    eprint!("{prompt}");
    io::stderr().flush().ok();

    let mut t = get_termios();
    let orig = t;
    t.c_lflag &= !ECHO;
    set_termios(&t);

    let mut s = String::new();
    io::stdin().lock().read_line(&mut s).ok();
    set_termios(&orig);
    eprintln!();

    ZeroString::from_string(s.trim_end_matches('\n').to_string())
}
