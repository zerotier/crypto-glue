/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use cfg_if::cfg_if;
use libc::{c_char, c_int};
use std::borrow::Cow;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::ptr;
use std::str;

type ErrType = libc::c_ulong;

/// Collection of [`Error`]s from OpenSSL.
///
/// [`Error`]: struct.Error.html
#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    /// Returns the contents of the OpenSSL error stack.
    #[cold]
    #[inline(never)]
    pub fn get() -> ErrorStack {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        ErrorStack(vec)
    }

    /// Pushes the errors back onto the OpenSSL error stack.
    pub fn put(&self) {
        for error in self.errors() {
            error.put();
        }
    }
}

impl ErrorStack {
    /// Returns the errors in the stack.
    pub fn errors(&self) -> &[Error] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return fmt.write_str("OpenSSL error");
        }

        let mut first = true;
        for err in &self.0 {
            if !first {
                fmt.write_str(", ")?;
            }
            write!(fmt, "{}", err)?;
            first = false;
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> io::Error {
        io::Error::new(io::ErrorKind::Other, e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> fmt::Error {
        fmt::Error
    }
}

/// An error reported from OpenSSL.
#[derive(Clone)]
pub struct Error {
    code: ErrType,
    file: ShimStr,
    line: c_int,
    func: Option<ShimStr>,
    data: Option<Cow<'static, str>>,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

impl Error {
    /// Returns the first error on the OpenSSL error stack.
    pub fn get() -> Option<Error> {
        unsafe {
            let mut file = ptr::null();
            let mut line = 0;
            let mut func = ptr::null();
            let mut data = ptr::null();
            let mut flags = 0;
            match ERR_get_error_all(&mut file, &mut line, &mut func, &mut data, &mut flags) {
                0 => None,
                code => {
                    // The memory referenced by data is only valid until that slot is overwritten
                    // in the error stack, so we'll need to copy it off if it's dynamic
                    let data = if flags & ffi::ERR_TXT_STRING != 0 {
                        let bytes = CStr::from_ptr(data as *const _).to_bytes();
                        let data = str::from_utf8(bytes).unwrap();
                        #[cfg(not(boringssl))]
                        let data = if flags & ffi::ERR_TXT_MALLOCED != 0 {
                            Cow::Owned(data.to_string())
                        } else {
                            Cow::Borrowed(data)
                        };
                        #[cfg(boringssl)]
                        let data = Cow::Borrowed(data);
                        Some(data)
                    } else {
                        None
                    };

                    let file = ShimStr::new(file);

                    let func = if func.is_null() {
                        None
                    } else {
                        Some(ShimStr::new(func))
                    };

                    Some(Error { code, file, line, func, data })
                }
            }
        }
    }

    /// Pushes the error back onto the OpenSSL error stack.
    pub fn put(&self) {
        self.put_error();

        unsafe {
            let data = match self.data {
                Some(Cow::Borrowed(data)) => Some((data.as_ptr() as *mut c_char, 0)),
                Some(Cow::Owned(ref data)) => {
                    let ptr = ffi::CRYPTO_malloc(
                        (data.len() + 1) as _,
                        concat!(file!(), "\0").as_ptr() as _,
                        line!() as _,
                    ) as *mut c_char;
                    if ptr.is_null() {
                        None
                    } else {
                        ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
                        *ptr.add(data.len()) = 0;
                        Some((ptr, ffi::ERR_TXT_MALLOCED))
                    }
                }
                None => None,
            };
            if let Some((ptr, flags)) = data {
                ffi::ERR_set_error_data(ptr, flags | ffi::ERR_TXT_STRING);
            }
        }
    }

    #[cfg(ossl300)]
    fn put_error(&self) {
        unsafe {
            ffi::ERR_new();
            ffi::ERR_set_debug(
                self.file.as_ptr(),
                self.line,
                self.func.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            );
            ffi::ERR_set_error(ffi::ERR_GET_LIB(self.code), ffi::ERR_GET_REASON(self.code), ptr::null());
        }
    }

    /// Returns the raw OpenSSL error code for this error.
    pub fn code(&self) -> ErrType {
        self.code
    }

    /// Returns the name of the library reporting the error, if available.
    pub fn library(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_lib_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the name of the function reporting the error.
    pub fn function(&self) -> Option<RetStr<'_>> {
        self.func.as_ref().map(|s| s.as_str())
    }

    /// Returns the reason for the error.
    pub fn reason(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_reason_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            Some(str::from_utf8(bytes).unwrap())
        }
    }

    /// Returns the name of the source file which encountered the error.
    pub fn file(&self) -> RetStr<'_> {
        self.file.as_str()
    }

    /// Returns the line in the source file which encountered the error.
    pub fn line(&self) -> u32 {
        self.line as u32
    }

    /// Returns additional data describing the error.
    #[allow(clippy::option_as_ref_deref)]
    pub fn data(&self) -> Option<&str> {
        self.data.as_ref().map(|s| &**s)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(library) = self.library() {
            builder.field("library", &library);
        }
        if let Some(function) = self.function() {
            builder.field("function", &function);
        }
        if let Some(reason) = self.reason() {
            builder.field("reason", &reason);
        }
        builder.field("file", &self.file());
        builder.field("line", &self.line());
        if let Some(data) = self.data() {
            builder.field("data", &data);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "error:{:08X}", self.code())?;
        match self.library() {
            Some(l) => write!(fmt, ":{}", l)?,
            None => write!(fmt, ":lib({})", ffi::ERR_GET_LIB(self.code()))?,
        }
        match self.function() {
            Some(f) => write!(fmt, ":{}", f)?,
            None => write!(fmt, ":func({})", ffi::ERR_GET_FUNC(self.code()))?,
        }
        match self.reason() {
            Some(r) => write!(fmt, ":{}", r)?,
            None => write!(fmt, ":reason({})", ffi::ERR_GET_REASON(self.code()))?,
        }
        write!(fmt, ":{}:{}:{}", self.file(), self.line(), self.data().unwrap_or(""))
    }
}

impl error::Error for Error {}

cfg_if! {
    if #[cfg(ossl300)] {
        use std::ffi::{CString};
        use ffi::ERR_get_error_all;

        type RetStr<'a> = &'a str;

        #[derive(Clone)]
        struct ShimStr(CString);

        impl ShimStr {
            unsafe fn new(s: *const c_char) -> Self {
                ShimStr(CStr::from_ptr(s).to_owned())
            }

            fn as_ptr(&self) -> *const c_char {
                self.0.as_ptr()
            }

            fn as_str(&self) -> &str {
                self.0.to_str().unwrap()
            }
        }
    } else {
        #[allow(bad_style)]
        unsafe extern "C" fn ERR_get_error_all(
            file: *mut *const c_char,
            line: *mut c_int,
            func: *mut *const c_char,
            data: *mut *const c_char,
            flags: *mut c_int,
        ) -> ErrType {
            let code = ffi::ERR_get_error_line_data(file, line, data, flags);
            *func = ffi::ERR_func_error_string(code);
            code
        }

        type RetStr<'a> = &'static str;

        #[derive(Clone)]
        struct ShimStr(*const c_char);

        impl ShimStr {
            unsafe fn new(s: *const c_char) -> Self {
                ShimStr(s)
            }

            fn as_ptr(&self) -> *const c_char {
                self.0
            }

            fn as_str(&self) -> &'static str {
                unsafe {
                    CStr::from_ptr(self.0).to_str().unwrap()
                }
            }
        }
    }
}

#[inline]
pub fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
pub fn cvt(r: c_int) -> Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

#[inline]
pub fn cvt_n(r: c_int) -> Result<c_int, ErrorStack> {
    if r < 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
