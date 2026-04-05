use anyhow::{bail, Result};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

pub fn check_arch() -> Result<()> {
    if std::env::consts::ARCH == "aarch64" {
        bail!("ARM64 architecture detected. This project currently only supports x86_64!");
    }
    Ok(())
}

/// Finds the Process ID (PID) of the running WeChat process.
///
/// # Safety
///
/// This function uses Windows Toolhelp32 snapshots to iterate through system processes.
/// It is marked unsafe because it relies on FFI calls to the Windows API.
pub unsafe fn find_wechat_pid() -> Result<u32> {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;
    let mut pe = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut target_pid = 0;

    if Process32FirstW(snap, &mut pe).is_ok() {
        loop {
            let name = OsString::from_wide(&pe.szExeFile)
                .into_string()
                .unwrap_or_default()
                .trim_matches('\0')
                .to_lowercase();

            if name == "weixin.exe" || name == "wechat.exe" {
                target_pid = pe.th32ProcessID;
                break;
            }
            if Process32NextW(snap, &mut pe).is_err() {
                break;
            }
        }
    }
    CloseHandle(snap)?;

    if target_pid == 0 {
        bail!("WeChat process not found in memory. Please ensure WeChat is logged in!");
    }

    Ok(target_pid)
}
