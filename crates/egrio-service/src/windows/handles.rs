use std::ptr::{null, null_mut, NonNull};

use uuid::Uuid;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess};

use super::identity::OwnedHandle;
use crate::shared_memory::{ChannelBinding, ChannelLayout};

#[derive(Debug)]
pub struct PacketKernelObjects {
    mapping: OwnedHandle,
    rx_data: OwnedHandle,
    rx_space: OwnedHandle,
    tx_data: OwnedHandle,
    tx_space: OwnedHandle,
    channel: MappedPacketChannel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DuplicatedPacketHandles {
    pub channel_id: Uuid,
    pub mapping: u64,
    pub rx_data_available: u64,
    pub rx_space_available: u64,
    pub tx_data_available: u64,
    pub tx_space_available: u64,
    pub mapping_len: u64,
}

impl PacketKernelObjects {
    pub fn new(layout: ChannelLayout, channel_id: Uuid) -> Result<Self, String> {
        let mapping_len = layout.mapping_len() as u64;
        let mapping = OwnedHandle::from_raw(unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                null(),
                PAGE_READWRITE,
                (mapping_len >> 32) as u32,
                mapping_len as u32,
                null(),
            )
        })?;
        let channel = MappedPacketChannel::initialize(mapping.raw(), layout, channel_id)?;
        let event = || OwnedHandle::from_raw(unsafe { CreateEventW(null(), 0, 0, null()) });
        Ok(Self {
            mapping,
            rx_data: event()?,
            rx_space: event()?,
            tx_data: event()?,
            tx_space: event()?,
            channel,
        })
    }

    pub fn channel(&self) -> &MappedPacketChannel {
        &self.channel
    }

    pub(super) fn rx_data_handle(&self) -> HANDLE {
        self.rx_data.raw()
    }

    pub(super) fn rx_space_handle(&self) -> HANDLE {
        self.rx_space.raw()
    }

    pub(super) fn tx_data_handle(&self) -> HANDLE {
        self.tx_data.raw()
    }

    pub(super) fn tx_space_handle(&self) -> HANDLE {
        self.tx_space.raw()
    }

    pub fn duplicate_into(
        &self,
        target_process: &OwnedHandle,
    ) -> Result<DuplicatedPacketHandles, String> {
        let mut duplicated = Vec::with_capacity(5);
        for source in [
            self.mapping.raw(),
            self.rx_data.raw(),
            self.rx_space.raw(),
            self.tx_data.raw(),
            self.tx_space.raw(),
        ] {
            match duplicate(source, target_process.raw()) {
                Ok(handle) => duplicated.push(handle),
                Err(error) => {
                    close_remote_handles(target_process.raw(), &duplicated);
                    return Err(error);
                }
            }
        }
        Ok(DuplicatedPacketHandles {
            channel_id: self.channel.binding().channel_id(),
            mapping: duplicated[0],
            rx_data_available: duplicated[1],
            rx_space_available: duplicated[2],
            tx_data_available: duplicated[3],
            tx_space_available: duplicated[4],
            mapping_len: self.channel.len() as u64,
        })
    }
}

impl DuplicatedPacketHandles {
    pub fn close_in_target(self, target_process: &OwnedHandle) {
        close_remote_handles(
            target_process.raw(),
            &[
                self.mapping,
                self.rx_data_available,
                self.rx_space_available,
                self.tx_data_available,
                self.tx_space_available,
            ],
        );
    }
}

#[derive(Debug)]
pub struct MappedPacketChannel {
    base: NonNull<u8>,
    len: usize,
    binding: ChannelBinding,
}

unsafe impl Send for MappedPacketChannel {}
unsafe impl Sync for MappedPacketChannel {}

impl MappedPacketChannel {
    fn initialize(
        mapping: HANDLE,
        layout: ChannelLayout,
        channel_id: Uuid,
    ) -> Result<Self, String> {
        let base = map_view(mapping)?;
        let binding = match unsafe {
            ChannelBinding::initialize(base.as_ptr(), layout.mapping_len(), layout, channel_id)
        } {
            Ok(binding) => binding,
            Err(error) => {
                unmap_view(base);
                return Err(format!(
                    "failed to initialize packet channel ABI: {error:?}"
                ));
            }
        };
        Ok(Self {
            base,
            len: layout.mapping_len(),
            binding,
        })
    }

    pub fn open(mapping: HANDLE, len: usize) -> Result<Self, String> {
        let base = map_view(mapping)?;
        let binding = match unsafe { ChannelBinding::from_raw(base.as_ptr(), len) } {
            Ok(binding) => binding,
            Err(error) => {
                unmap_view(base);
                return Err(format!("invalid packet channel ABI: {error:?}"));
            }
        };
        Ok(Self { base, len, binding })
    }

    pub const fn binding(&self) -> ChannelBinding {
        self.binding
    }

    pub const fn len(&self) -> usize {
        self.len
    }
}

impl Drop for MappedPacketChannel {
    fn drop(&mut self) {
        unmap_view(self.base);
    }
}

fn map_view(mapping: HANDLE) -> Result<NonNull<u8>, String> {
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0) };
    NonNull::new(view.Value.cast()).ok_or_else(|| std::io::Error::last_os_error().to_string())
}

fn unmap_view(base: NonNull<u8>) {
    unsafe {
        UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
            Value: base.as_ptr().cast(),
        })
    };
}

fn duplicate(source: HANDLE, target_process: HANDLE) -> Result<u64, String> {
    let mut target = null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            target_process,
            &mut target,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(
            std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32).to_string(),
        );
    }
    Ok(target as usize as u64)
}

pub(super) fn duplicate_for_current_process(source: HANDLE) -> Result<OwnedHandle, String> {
    let current = unsafe { GetCurrentProcess() };
    let duplicated = duplicate(source, current)?;
    let duplicated = usize::try_from(duplicated)
        .map_err(|_| "duplicated handle does not fit usize".to_string())?;
    OwnedHandle::from_raw(duplicated as HANDLE)
}

fn close_remote_handles(target_process: HANDLE, handles: &[u64]) {
    for &handle in handles {
        let Ok(handle) = usize::try_from(handle) else {
            continue;
        };
        let mut local = null_mut();
        if unsafe {
            DuplicateHandle(
                target_process,
                handle as HANDLE,
                GetCurrentProcess(),
                &mut local,
                0,
                0,
                DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE,
            )
        } != 0
            && !local.is_null()
        {
            unsafe { CloseHandle(local) };
        }
    }
}
