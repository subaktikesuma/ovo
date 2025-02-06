use std::ffi::c_void;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use anyhow::anyhow;
use nix::errno::Errno;
use nix::{libc, NixPath};
use nix::libc::{free, getsockopt, malloc, mmap, sockaddr_in, socklen_t};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};

pub struct Driver {
    sock: OwnedFd,
    verbose: bool,
}

fn driver_id() -> Result<OwnedFd, anyhow::Error> {
    let address_families = [
        AddressFamily::Decnet,
        AddressFamily::NetBeui,
        AddressFamily::Security,
        AddressFamily::Key,
        AddressFamily::Netlink,
        AddressFamily::Packet,
        AddressFamily::Ash,
        AddressFamily::Econet,
        AddressFamily::AtmSvc,
        AddressFamily::Rds,
        AddressFamily::Sna,
        AddressFamily::Irda,
        AddressFamily::Pppox,
        AddressFamily::Wanpipe,
        AddressFamily::Llc,
        AddressFamily::Can,
        AddressFamily::Tipc,
        AddressFamily::Bluetooth,
        AddressFamily::Iucv,
        AddressFamily::RxRpc,
        AddressFamily::Isdn,
        AddressFamily::Phonet,
        AddressFamily::Ieee802154,
        AddressFamily::Caif,
        AddressFamily::Alg,
        AddressFamily::Vsock,
    ];

    for af in address_families.iter() {
        match socket(
            *af,
            SockType::SeqPacket,
            SockFlag::empty(),
            None,
        ) {
            Ok(_) => {
                continue
            }
            Err(Errno::ENOKEY) => {
                match socket(
                    *af,
                    SockType::Raw,
                    SockFlag::empty(),
                    None,
                ) {
                    Ok(fd) => {
                        return Ok(fd);
                    }
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        }
    }
    Err(anyhow!("无法找到OVO协议族"))
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriverFunctionRequest {
    GetProcessPid = 0,
    IsProcessAlivePid = 1,
    AttachProcess = 2,
    GetProcessModuleBase = 3,
    ReadProcessMemoryIoremap = 4,
    WriteProcessMemoryIoremap = 5,
    AccessProcessVm = 6,
    ReadProcessMemory = 7,
    WriteProcessMemory = 8,
    RemapMemory = 9,
}

impl Driver {
    pub fn new() -> Result<Self, anyhow::Error> {
        let sock = driver_id()?;
        let verbose = std::env::var("RUST_VERBOSE").unwrap_or_else(|_| "0".to_string()) == "1";
        Ok(Self {
            sock,
            verbose,
        })
    }

    pub fn verbose(&self) -> bool {
        self.verbose
    }

    pub fn get_process_pid(&self, package: &str) -> Result<i32, anyhow::Error> {
        unsafe {
            let mut data = malloc(package.len() + 1);
            std::ptr::copy_nonoverlapping(package.as_ptr(), data as *mut u8, package.len());
            let mut len: socklen_t = (package.len() + 1) as socklen_t;
            if getsockopt(
                self.sock.as_raw_fd(),
                len as i32,
                DriverFunctionRequest::GetProcessPid as i32,
                data,
                &mut len
            ) < 0 && Errno::last_raw() != 2033 {
                free(data);
                return Err(anyhow!("get process pid failed: {:?}", Errno::last()));
            }
            let pid = *(data as *const i32);
            free(data);
            Ok(pid)
        }
    }

    pub fn is_process_alive_pid(&self, pid: i32) -> bool {
        unsafe {
            let mut len: socklen_t = 0;
            if getsockopt(
                self.sock.as_raw_fd(),
                pid,
                DriverFunctionRequest::IsProcessAlivePid as i32,
                std::ptr::null_mut(),
                &mut len
            ) < 0 && Errno::last_raw() != 2033 {
                eprintln!("is process alive failed: {:?}", Errno::last());
                return false
            }
            len == 1
        }
    }

    pub fn attach_process(&self, pid: i32) -> bool {
        unsafe {
            let mut len: socklen_t = 0;
            if getsockopt(
                self.sock.as_raw_fd(),
                pid,
                DriverFunctionRequest::AttachProcess as i32,
                std::ptr::null_mut(),
                &mut len
            ) < 0 && Errno::last_raw() != 2033 {
                println!("attach process failed: {:?}", Errno::last());
                return false
            }
            true
        }
    }

    pub fn get_process_module_base(&self, module: &str, vm_flag: i32) -> Result<u64, anyhow::Error> {
        unsafe {
            let mut len: socklen_t = (module.len() + 1) as socklen_t;
            if len < 8 {
                len = 8
            }
            let mut data = malloc(len as usize);
            std::ptr::copy_nonoverlapping(module.as_ptr(), data as *mut u8, module.len());
            let mut len: socklen_t = (module.len() + 1) as socklen_t;
            if getsockopt(
                self.sock.as_raw_fd(),
                vm_flag,
                DriverFunctionRequest::GetProcessModuleBase as i32,
                data,
                &mut len
            ) < 0 && Errno::last_raw() != 2033 {
                free(data);
                return Err(anyhow!("get process module base failed: {:?}", Errno::last()));
            }
            let base = *(data as *const u64);
            free(data);
            Ok(base)
        }
    }

    pub fn read_process_memory_ioremap(&self, addr: u64, buffer: &mut [u8]) -> Result<usize, anyhow::Error> {
        unsafe {
            let dest = buffer.as_mut_ptr() as *mut socklen_t;
            let ret = getsockopt(
                self.sock.as_raw_fd(),
                buffer.len() as i32,
                DriverFunctionRequest::ReadProcessMemoryIoremap as i32,
                addr as *mut c_void,
                dest
            );
            if self.verbose {
                println!("read_process_memory_ioremap(0x{:X}, {}) -> {}, data: {:?}", addr, buffer.len(), ret, buffer);
            }
            if ret < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("read process memory ioremap failed: {:?}", Errno::last()));
            }
            Ok(buffer.len())
        }
    }

    pub fn read_vec(&self, addr: u64, size: usize) -> Result<Vec<u8>, anyhow::Error> {
        let mut ret = Vec::new();
        ret.resize(size, 0);
        self.read_process_memory_ioremap(addr, ret.as_mut_slice())?;
        if self.verbose {
            println!("read_vec(0x{:X}, {}) -> {:?}", addr, size, ret);
        }
        Ok(ret)
    }

    pub fn read<T: Sized + Copy>(&self, addr: u64) -> Result<T, anyhow::Error> {
        let vec = self.read_vec(addr, size_of::<T>())?;
        //println!("vec: {:?}, {}", vec, size_of::<T>());
        unsafe { Ok(*(vec.as_ptr() as *const T)) }
    }

    pub fn write_process_memory_ioremap(&self, addr: u64, buffer: &[u8]) -> Result<usize, anyhow::Error> {
        unsafe {
            let dest = buffer.as_ptr() as *mut socklen_t;
            if getsockopt(
                self.sock.as_raw_fd(),
                buffer.len() as i32,
                DriverFunctionRequest::WriteProcessMemoryIoremap as i32,
                addr as *mut c_void,
                dest
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("write process memory ioremap failed: {:?}", Errno::last()));
            }
            Ok(buffer.len())
        }
    }

    pub fn access_process_vm(&self, from: i32, from_addr: u64, to: i32, to_addr: u64, len: usize) -> Result<usize, anyhow::Error> {
        struct ReqAccessProcessVm {
            from: i32,
            from_addr: u64,
            to: i32,
            to_addr: u64,
            size: usize,
        }

        unsafe {
            let mut data_len: socklen_t = size_of::<ReqAccessProcessVm>() as socklen_t;
            let data = ReqAccessProcessVm {
                from,
                from_addr,
                to,
                to_addr,
                size: len,
            };
            if getsockopt(
                self.sock.as_raw_fd(),
                len as i32,
                DriverFunctionRequest::WriteProcessMemoryIoremap as i32,
                &data as *const ReqAccessProcessVm as *mut c_void,
                &mut data_len
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("write process memory ioremap failed: {:?}", Errno::last()));
            }
            Ok(len)
        }
    }

    pub fn read_process_memory(&self, addr: u64, buffer: &mut [u8]) -> Result<usize, anyhow::Error> {
        unsafe {
            let dest = buffer.as_mut_ptr() as *mut socklen_t;
            if getsockopt(
                self.sock.as_raw_fd(),
                buffer.len() as i32,
                DriverFunctionRequest::ReadProcessMemory as i32,
                addr as *mut c_void,
                dest
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("read process memory failed: {:?}", Errno::last()));
            }
            Ok(buffer.len())
        }
    }

    pub fn write_process_memory(&self, addr: u64, buffer: &[u8]) -> Result<usize, anyhow::Error> {
        unsafe {
            let dest = buffer.as_ptr() as *mut socklen_t;
            if getsockopt(
                self.sock.as_raw_fd(),
                buffer.len() as i32,
                DriverFunctionRequest::WriteProcessMemory as i32,
                addr as *mut c_void,
                dest
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("write process memory failed: {:?}", Errno::last()));
            }
            Ok(buffer.len())
        }
    }

    pub unsafe fn remap_memory(&self, addr: u64, size: usize) -> Result<*mut c_void, anyhow::Error> {
         if getsockopt(
            self.sock.as_raw_fd(),
            size as i32,
            DriverFunctionRequest::RemapMemory as i32,
            addr as *mut c_void,
            addr as *mut socklen_t
        ) < 0 && Errno::last_raw() != 2033 {
            return Err(anyhow!("remap memory failed: {:?}", Errno::last()));
        }
        let buf = mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            self.sock.as_raw_fd(),
            0,
        );
        if buf == libc::MAP_FAILED {
            return Err(anyhow!("remap memory failed: {:?}", Errno::last()));
        }
        Ok(buf)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
    }
}