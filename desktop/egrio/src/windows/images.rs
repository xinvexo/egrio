//! Decodes PNG data into a bitmap a WinUI `Image` shows: the bytes go into
//! an in-memory COM stream (`SHCreateMemStream`), wrapped as a WinRT random
//! access stream (`CreateRandomAccessStreamOverStream`), which
//! `BitmapImage.SetSource` decodes at once.

use windows_core::{Interface, Result};

use super::bindings::{
    BitmapImage, CreateRandomAccessStreamOverStream, IBitmapSource, IRandomAccessStream,
    SHCreateMemStream, BSOS_DEFAULT,
};

pub fn bitmap(png: &[u8]) -> Result<BitmapImage> {
    // SAFETY: the stream copies the bytes.
    let stream = unsafe { SHCreateMemStream(png.as_ptr(), png.len() as u32) }
        .ok_or_else(|| windows_core::Error::from_thread())?;
    let mut random: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: an IStream in, the IID of the interface asked for, a pointer
    // that receives it.
    unsafe {
        CreateRandomAccessStreamOverStream(
            stream.as_raw(),
            BSOS_DEFAULT,
            &IRandomAccessStream::IID,
            &mut random,
        )
        .ok()?;
    }
    // SAFETY: the call above returned an owned IRandomAccessStream.
    let random = unsafe { IRandomAccessStream::from_raw(random) };
    let bitmap = BitmapImage::new()?;
    bitmap.cast::<IBitmapSource>()?.SetSource(&random)?;
    Ok(bitmap)
}
