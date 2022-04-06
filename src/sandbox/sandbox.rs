use std::io;
use std::process::{Command, Child};
use std::{convert::TryInto, marker::PhantomData};
use seccomp::{Action, Context, Rule};
use std::os::unix::prelude::AsRawFd;
use std::{os::unix::io::RawFd};
use std::fs::File;
// const DEFAULT_ALLOWED_CALLS: &[i64] = &[
//     libc::SYS_exit,
//     libc::SYS_clone,
//     libc::SYS_read,
//     libc::SYS_write,
//     libc::SYS_execve,
// ];
const DEFAULT_DENY_CALLS: &[i64] = &[
    // libc::SYS_socketpair,
    libc::SYS_ptrace,
    libc::SYS_fork,
    // libc::SYS_read,
    libc::SYS_kill,
];
const SECCOMP_SET_MODE_FILTER: i32 = 1;

/// Filter defines allowed sys calls.
#[derive(Debug, Clone)]
pub struct Filter(Vec<u8>);

impl Default for Filter {
    fn default() -> Self {
        Self::new(DEFAULT_DENY_CALLS)
    }
}
    
impl Filter {
    /// Create a new filter.
    pub fn new(deny_calls: &[i64]) -> Filter {
        let cx = match Context::default(Action::Allow) {
            Ok(mut cx) => {
                for &call in deny_calls {
                    println!("add a call {:?}", &call);
                    match cx.add_rule(Rule::new(call as usize, None, Action::Errno(libc::EPERM))) {
                        Ok(_) => {}
                        Err(_e) => panic!("")
                    }
                }
                from_cx(cx)
            },
            Err(_e) => panic!("")
        };
        Filter(cx.unwrap().to_vec())
    }

    /// Apply the filter.
    pub fn activate(&self) -> io::Result<()> {
                let result = unsafe{libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)};
                if result != 0 {
                    return Err(io::Error::last_os_error())
                }
                let prog = LibcSockFprog {
                    len: (self.0.len() / 8).try_into().expect("too long program"),
                    prog: self.0.as_ptr().cast(),
                    phantom: PhantomData,
                };
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_seccomp,
                        // operation
                        SECCOMP_SET_MODE_FILTER,
                        // flags
                        0,
                        // prog
                        &prog as *const _,
                    )
                };
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
        }
}

fn from_cx(cx: Context) -> io::Result<Vec<u8>> {
    let f = File::create("temp.rs")?;
    let fd: RawFd = f.as_raw_fd();

    match cx.export(fd) {
        Ok(_) => {
            let data = std::fs::read("temp.rs")?;
            Ok(data)
        }
        Err(_e) => Err(io::Error::last_os_error())
    }
}

#[repr(C)]
struct LibcSockFprog<'a> {
    len: libc::c_ushort,
    prog: *const libc::c_void,
    phantom: PhantomData<&'a ()>,
}

/// A sandbox environment for the process.
pub struct Sandbox {}

impl Default for Sandbox {
    fn default() -> Self {
           Self::new()
         }
     }
    
impl Sandbox {
    /// Creates a new sandbox.
    pub fn new() -> Sandbox {
        Sandbox {}
    }
    /// Activate a BPF filter and spawn the command. 
    pub fn start(&self, command: &mut Command) -> io::Result<Child> {
        match Filter::new(DEFAULT_DENY_CALLS).activate() {
            Ok(_) => command.spawn(),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

}

