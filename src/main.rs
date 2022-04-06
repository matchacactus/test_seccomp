use test_seccomp::sandbox::sandbox::{Sandbox, Filter};
use nix::unistd::ForkResult::{Parent, Child};
use nix::{unistd::{fork, write}};
use std::{thread, time};
const DEFAULT_DENY_CALLS: &[i64] = &[
    libc::SYS_write,
    libc::SYS_clock_nanosleep,
];
fn main() {
    match unsafe{fork()} {
        Ok(Parent { child, .. }) => {
            println!("outer parent process, new child has pid: {}", child);
        }
        Ok(Child) => {
            match Filter::new(DEFAULT_DENY_CALLS).activate() {
                Ok(_) => {
                    let mut i = 0;
                    while i < 10 {
                        write(libc::STDOUT_FILENO, "outer child process\n".as_bytes()).ok();
                    i += 1}
                },
                Err(_) => panic!("")
            };

            match unsafe{fork()} {
                Ok(Parent { child, .. }) => {
                    println!("inner parent process, new child has pid: {}", child);
                }
                Ok(Child) => {
                    // Unsafe to use `println!` (or `unwrap`) here. See Safety.
                    match Filter::new(DEFAULT_DENY_CALLS).activate() {
                        Ok(_) => {
                            loop {
                                write(libc::STDOUT_FILENO, "inner child process\n".as_bytes()).ok();
                                thread::sleep(time::Duration::from_millis(5000));
                            }
                        },
                        Err(_) => panic!("")
                    }
                }
                Err(_) => println!("Fork failed"),
            }
        }
        Err(_) => println!("Fork failed"),
    }

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        println!("i am a parent");
    }
}