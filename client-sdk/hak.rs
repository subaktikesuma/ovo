use std::ffi::c_void;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use anyhow::anyhow;
use std::mem::MaybeUninit;
use nix::errno::Errno;
use nix::{libc, NixPath};
use nix::libc::{c_int, free, getsockopt, ioctl, malloc, mmap, sockaddr_in, socklen_t};
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

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DriverIoctlRequest {
    TouchClickUp = 1001,
    TouchClickDown = 1000,
    TouchSwipeStart = 1002,
    TouchSwipeMove = 1003,
    TouchSwipeEnd = 1004,
    TouchSwipeSoon = 1005,
    TouchMove = 1006,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OvOTouchBase {
    pub slot: c_int,
    pub x: c_int,
    pub y: c_int,
    pub pressure: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OvOTouchSoon {
    pub start: OvOTouchBase,
    pub end: OvOTouchBase,
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
        if buffer.len() < 2 {
            return Err(anyhow!("invalid buffer size: {}", buffer.len()));
        }
        unsafe {
            let dest = buffer.as_mut_ptr() as *mut socklen_t;
            let ret = getsockopt(
                self.sock.as_raw_fd(),
                buffer.len() as i32,
                DriverFunctionRequest::ReadProcessMemoryIoremap as i32,
                addr as *mut c_void,
                dest
            );
            // if self.verbose {
            //     println!("read_process_memory_ioremap(0x{:X}, {}) -> {}, data: {:?}", addr, buffer.len(), ret, buffer);
            // }
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
        Ok(ret)
    }

    pub fn read<T: Sized + Copy>(&self, addr: u64) -> Result<T, anyhow::Error> {
        if addr <= 0x1000 {
            return Err(anyhow!("invalid address: 0x{:X}", addr));
        }
        if size_of::<T>() == 0 {
            return Err(anyhow!("invalid size: {}", size_of::<T>()));
        }
        let vec = self.read_vec(addr, size_of::<T>())?;
        //println!("vec: {:?}, {}", vec, size_of::<T>());
        unsafe { Ok(*(vec.as_ptr() as *const T)) }
    }

    pub fn read_f32_vector(&self, addr: u64, size: usize) -> Result<Vec<f32>, anyhow::Error> {
        let mut ret = Vec::new();
        ret.resize(size, 0.0);
        self.read_process_memory_ioremap(addr, unsafe { std::slice::from_raw_parts_mut(ret.as_mut_ptr() as *mut u8, size_of::<f32>() * size) })?;
        Ok(ret)
    }

    /**
     * In some devices, an error may be triggered from BPF_CGROUP_RUN-REG_GETSOCKOPT when use read_via_uninit.
     * Although the memory has been successfully read, it still needs to return a errno to you!
     */
    pub fn read_via_uninit<T: Sized + Copy>(&self, addr: u64) -> Result<T, anyhow::Error> {
        let data = unsafe {
            let mut data = MaybeUninit::<T>::uninit();
            self.read_process_memory_ioremap(addr, std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u8, size_of::<T>()))?;
            data.assume_init()
        };
        Ok(data)
    }

    /// 读取UE4的FString
    pub fn read_fstring(&self, addr: u64) -> Result<String, anyhow::Error> {
        let len = self.read::<u32>(addr + 8)? as usize;
        if len == 0 {
            return Ok("".to_string());
        }
        let player_name_private = self.read::<u64>(addr)?;
        let mut player_name = vec![];
        unsafe { self.read_to_utf8(player_name_private as *const u16, &mut player_name, len - 1)?; }
        String::from_utf8(player_name).map_err(|e| anyhow!("read fstring failed: {:?}", e))
    }

    pub unsafe fn read_to_utf8(&self, ptr: *const u16, buf: &mut Vec<u8>, length: usize) -> Result<(), anyhow::Error> {
        let mut temp_utf16 = ptr;
        let end = ptr.add(length);

        while temp_utf16 < end {
            let utf16_char = self.read::<u16>(temp_utf16 as u64)?;

            if utf16_char <= 0x007F {
                buf.push(utf16_char as u8);
            } else if utf16_char <= 0x07FF {
                buf.push(((utf16_char >> 6) | 0xC0) as u8);
                buf.push(((utf16_char & 0x3F) | 0x80) as u8);
            } else {
                buf.push(((utf16_char >> 12) | 0xE0) as u8);
                buf.push(((utf16_char >> 6 & 0x3F) | 0x80) as u8);
                buf.push(((utf16_char & 0x3F) | 0x80) as u8);
            }

            temp_utf16 = temp_utf16.add(1);
        }
        Ok(())
    }

    pub unsafe fn get_utf8(&self, buf: *mut u8, str: usize) -> Result<(), anyhow::Error> {
        let mut buf16 = [0u16; 16];
        self.read_process_memory_ioremap(str as u64, std::slice::from_raw_parts_mut(buf16.as_mut_ptr() as *mut u8, 28))?;

        let mut temp_utf16 = buf16.as_ptr();
        let mut temp_utf8 = buf;
        let utf8_end = temp_utf8.add(32);

        while temp_utf16 < buf16.as_ptr().add(28) {
            let utf16_char = *temp_utf16;

            if utf16_char <= 0x007F && temp_utf8.add(1) < utf8_end {
                *temp_utf8 = utf16_char as u8;
                temp_utf8 = temp_utf8.add(1);
            } else if utf16_char >= 0x0080 && utf16_char <= 0x07FF && temp_utf8.add(2) < utf8_end {
                *temp_utf8 = ((utf16_char >> 6) | 0xC0) as u8;
                *temp_utf8.add(1) = ((utf16_char & 0x3F) | 0x80) as u8;
                temp_utf8 = temp_utf8.add(2);
            } else if utf16_char >= 0x0800 && utf16_char <= 0xFFFF && temp_utf8.add(3) < utf8_end {
                *temp_utf8 = ((utf16_char >> 12) | 0xE0) as u8;
                *temp_utf8.add(1) = (((utf16_char >> 6) & 0x3F) | 0x80) as u8;
                *temp_utf8.add(2) = ((utf16_char & 0x3F) | 0x80) as u8;
                temp_utf8 = temp_utf8.add(3);
            } else {
                break;
            }
            temp_utf16 = temp_utf16.add(1);
        }
        Ok(())
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

    pub fn write_f32(&self, addr: u64, value: f32) -> Result<usize, anyhow::Error> {
        let mut buffer = Vec::new();
        buffer.resize(size_of::<f32>(), 0);
        unsafe {
            std::ptr::copy_nonoverlapping(&value as *const f32 as *const u8, buffer.as_mut_ptr(), size_of::<f32>());
        }
        self.write_process_memory_ioremap(addr, buffer.as_slice())
    }

    pub fn write_f32_vector(&self, addr: u64, value: &[f32]) -> Result<usize, anyhow::Error> {
        let mut buffer = Vec::new();
        buffer.resize(size_of::<f32>() * value.len(), 0);
        unsafe {
            std::ptr::copy_nonoverlapping(value.as_ptr() as *const u8, buffer.as_mut_ptr(), size_of::<f32>() * value.len());
        }
        self.write_process_memory_ioremap(addr, buffer.as_slice())
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

    pub fn touch_down(&self, slot: i32, x: i32, y: i32, pressure: i32) -> Result<(), anyhow::Error> {
        let click = OvOTouchBase {
            slot,
            x,
            y,
            pressure,
        };
        unsafe {
            if ioctl(
                self.sock.as_raw_fd(),
                DriverIoctlRequest::TouchClickDown as i32,
                &click as *const OvOTouchBase
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("touch click down failed: {:?}", Errno::last()));
            }
        }
        Ok(())
    }

    pub fn touch_up(&self, slot: i32) -> Result<(), anyhow::Error> {
        let click = OvOTouchBase {
            slot,
            x: 0,
            y: 0,
            pressure: 0,
        };
        unsafe {
            if ioctl(
                self.sock.as_raw_fd(),
                DriverIoctlRequest::TouchClickUp as i32,
                &click as *const OvOTouchBase
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("touch click up failed: {:?}", Errno::last()));
            }
        }
        Ok(())
    }

    pub fn long_click(&self, slot: i32, x: i32, y: i32, pressure: i32, duration: u64) -> Result<(), anyhow::Error> {
        unsafe {
            self.touch_down(slot, x, y, pressure)?;
            std::thread::sleep(std::time::Duration::from_millis(duration));
            self.touch_up(slot)?;
        }
        Ok(())
    }

    pub fn touch_move(&self, slot: i32, x: i32, y: i32, pressure: i32) -> Result<(), anyhow::Error> {
        let click = OvOTouchBase {
            slot,
            x,
            y,
            pressure,
        };
        unsafe {
            if ioctl(
                self.sock.as_raw_fd(),
                DriverIoctlRequest::TouchMove as i32,
                &click as *const OvOTouchBase
            ) < 0 && Errno::last_raw() != 2033 {
                return Err(anyhow!("touch_move failed: {:?}", Errno::last()));
            }
        }
        Ok(())
    }

    // pub fn swipe_start(&self, slot: i32, x: u32, y: u32, pressure: i32) -> Result<(), anyhow::Error> {
    //     unsafe {
    //         let click = OvOTouchBase {
    //             slot,
    //             x,
    //             y,
    //             pressure,
    //         };
    //         if ioctl(
    //             self.sock.as_raw_fd(),
    //             DriverIoctlRequest::TouchSwipeStart as i32,
    //             &click as *const OvOTouchBase
    //         ) < 0 && Errno::last_raw() != 2033 {
    //             return Err(anyhow!("swipe_start failed: {:?}", Errno::last()));
    //         }
    //     }
    //     Ok(())
    // }
    //
    // pub fn swipe_move(&self, slot: i32, x: u32, y: u32) -> Result<(), anyhow::Error> {
    //     unsafe {
    //         let click = OvOTouchBase {
    //             slot,
    //             x,
    //             y,
    //             pressure: 0,
    //         };
    //         if ioctl(
    //             self.sock.as_raw_fd(),
    //             DriverIoctlRequest::TouchSwipeMove as i32,
    //             &click as *const OvOTouchBase
    //         ) < 0 && Errno::last_raw() != 2033 {
    //             return Err(anyhow!("swipe_move failed: {:?}", Errno::last()));
    //         }
    //     }
    //     Ok(())
    // }
    //
    // pub fn swipe_end(&self, slot: i32) -> Result<(), anyhow::Error> {
    //     unsafe {
    //         let click = OvOTouchBase {
    //             slot,
    //             x: 0,
    //             y: 0,
    //             pressure: 0,
    //         };
    //         if ioctl(
    //             self.sock.as_raw_fd(),
    //             DriverIoctlRequest::TouchSwipeEnd as i32,
    //             &click as *const OvOTouchBase
    //         ) < 0 && Errno::last_raw() != 2033 {
    //             return Err(anyhow!("swipe_end failed: {:?}", Errno::last()));
    //         }
    //     }
    //     Ok(())
    // }
    //
    // pub fn swipe_soon(&self, slot: i32, x1: u32, y1: u32, x2: u32, y2: u32) -> Result<(), anyhow::Error> {
    //     unsafe {
    //         let click = OvOTouchSoon {
    //             start: OvOTouchBase {
    //                 slot,
    //                 x: x1,
    //                 y: y1,
    //                 pressure: 30,
    //             },
    //             end: OvOTouchBase {
    //                 slot,
    //                 x: x2,
    //                 y: y2,
    //                 pressure: 30,
    //             },
    //         };
    //         if ioctl(
    //             self.sock.as_raw_fd(),
    //             DriverIoctlRequest::TouchSwipeSoon as i32,
    //             &click as *const OvOTouchSoon
    //         ) < 0 && Errno::last_raw() != 2033 {
    //             return Err(anyhow!("swipe_soon failed: {:?}", Errno::last()));
    //         }
    //     }
    //     Ok(())
    // }
}

impl Drop for Driver {
    fn drop(&mut self) {
    }
}