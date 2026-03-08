use core::fmt;

pub mod nix_lock {
    use std::ffi::c_void;
    use std::ptr::NonNull;

    use nix::errno::Errno;

    use crate::platform::MemoryLockError;
    /// Unlock memory on drop for Unix-based systems.
    pub fn munlock_nix(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
        unsafe {
            Errno::clear();
            let ptr = NonNull::new_unchecked(ptr as *mut c_void);
            nix::sys::mman::munlock(ptr, len).map_err(|e| {
                MemoryLockError::new(format!("munlock: {} (0x{:x})", e.desc(), e as i32))
            })?;
        }
        Ok(())
    }

    pub fn mlock_nix(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
        unsafe {
            Errno::clear();
            let ptr = NonNull::new_unchecked(ptr as *mut c_void);
            nix::sys::mman::mlock(ptr, len).map_err(|e| {
                MemoryLockError::new(format!("mlock: {} (0x{:x})", e.desc(), e as i32))
            })?;
        }
        Ok(())
    }
}

pub mod region_lock {
    pub struct RegionError(pub region::Error);
    use core::fmt;

    pub fn munlock_region(ptr: *const u8, len: usize) -> Result<(), RegionError> {
        let res: Result<(), region::Error> = region::unlock(ptr, len);
        if res.is_err() {
            return Err(RegionError::convert(res));
        }
        Ok(())
    }

    pub fn mlock_region(ptr: *const u8, len: usize) -> Result<region::LockGuard, RegionError> {
        let guard: Result<region::LockGuard, region::Error> = region::lock(ptr, len);
        if guard.is_err() {
            return Err(RegionError::convert(guard));
        }
        let unwrap_guard: region::LockGuard = guard.unwrap();
        Ok(unwrap_guard)
    }

    impl fmt::Debug for RegionError {
        #[inline]
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self.0 {
                region::Error::UnmappedRegion => write!(f, "Queried memory is unmapped"),
                region::Error::InvalidParameter(param) => {
                    write!(f, "Invalid parameter value: {}", param)
                }
                region::Error::ProcfsInput(ref input) => {
                    write!(f, "Invalid procfs input: {}", input)
                }
                region::Error::SystemCall(ref error) => write!(f, "System call failed: {}", error),
                region::Error::MachCall(code) => write!(f, "macOS kernel call failed: {}", code),
            }
        }
    }
    impl RegionError {
        pub fn convert<T>(res: Result<T, region::Error>) -> Self {
            unsafe {
                let reg_err: Self = Self(res.unwrap_err_unchecked());
                reg_err
            }
        }
    }
}
