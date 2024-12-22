#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::collections::HashSet;
use std::ffi::CString;
use std::io::stdin;
use anyhow::Result;
use wmi::{COMLibrary, WMIConnection, WMIError};
use serde::Deserialize;
use walkdir::WalkDir;
use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows::Win32::Security::Authorization::ConvertStringSidToSidA;
use windows::Win32::UI::Shell::DeleteProfileA;

#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub domain: Option<String>,
    pub username: Option<String>,
    pub sid: String,
    pub health_status: u8,
    pub roaming_configured: bool,
    pub status: u32,
    pub loaded: bool,
    pub size: Option<u64>,
}

#[derive(Deserialize, Debug)]
struct Win32_UserProfile {
    SID: String,
    HealthStatus: u8,
    RoamingConfigured: bool,
    Status: u32,
    Special: bool,
    LocalPath: String,
    Loaded: bool,
}

#[derive(Debug)]
struct AccountInfo {
    username: String,
    domain_name: String,
}

struct WinPointer {
    inner: PSID,
}

impl Drop for WinPointer {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.inner.0));
        }
    }
}

fn get_user_profiles(wmi_con: &WMIConnection) -> Result<Vec<ProfileInfo>, WMIError> {
    let win32_up: Vec<Win32_UserProfile> = wmi_con.query()?;
    let vec = win32_up
        .iter()
        .filter(|up| !up.Special)
        .filter(|up| up.SID.starts_with("S-1-5-21-"))
        .map(|up| {
            let account_info = lookup_account_by_sid(&up.SID).ok();
            ProfileInfo {
                domain: account_info.as_ref().map(|a| a.domain_name.clone()),
                username: account_info
                    .as_ref()
                    .map(|account| account.username.clone()),
                sid: up.SID.clone(),
                health_status: up.HealthStatus,
                roaming_configured: up.RoamingConfigured,
                status: up.Status,
                loaded: up.Loaded,
                size: if up.Loaded {
                    None
                } else {
                    get_dir_size(&up.LocalPath).ok()
                },
            }
        })
        .collect();
    Ok(vec)
}

fn lookup_account_by_sid(sid_str: &str) -> Result<AccountInfo> {
    let sid_c_string = CString::new(sid_str)?;
    let mut sid_ptr = WinPointer {
        inner: PSID::default(),
    };

    unsafe {
        ConvertStringSidToSidA(
            PCSTR::from_raw(sid_c_string.as_ptr() as *const u8),
            &mut sid_ptr.inner,
        )?;
    }

    let mut name: [u16; 256] = [0; 256];
    let mut name_size = name.len() as u32;
    let name_pwstr = PWSTR::from_raw(name.as_mut_ptr());
    let mut domain_name: [u16; 256] = [0; 256];
    let mut domain_name_size = domain_name.len() as u32;
    let domain_name_pwstr = PWSTR::from_raw(domain_name.as_mut_ptr());
    let mut sid_name_use = SID_NAME_USE::default();

    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid_ptr.inner,
            name_pwstr,
            &mut name_size,
            domain_name_pwstr,
            &mut domain_name_size,
            &mut sid_name_use,
        )?;

        Ok(AccountInfo {
            username: name_pwstr.to_string()?,
            domain_name: domain_name_pwstr.to_string()?,
        })
    }
}

fn delete_user_profile(sid_str: &str) -> Result<()> {
    let sid_c_string = CString::new(sid_str)?;
    unsafe {
        DeleteProfileA(
            PCSTR::from_raw(sid_c_string.as_ptr() as *const u8),
            PCSTR::null(),
            PCSTR::null(),
        )?;
    }
    Ok(())
}

fn get_dir_size(path: &String) -> Result<u64> {
    Ok(WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|f| f.metadata().map_or(0, |f| f.len()))
        .sum())
}

fn main() -> Result<()> {
    let com_con = COMLibrary::new()?;
    let wmi_con = WMIConnection::new(com_con)?;
    let mut user_profiles = get_user_profiles(&wmi_con)?;
    user_profiles.sort_by_key(|k| k.username.clone());

    println!("{0: <5} | {1: <48} | {2: <15} | {3: <20} | {4: <7} | {5: <6} | {6}", "ID", "SID", "Domain", "Username", "Roaming", "Loaded", "Size");
    for (key, profile) in user_profiles.clone().into_iter().enumerate() {
        println!("{0: <5} | {1: <48} | {2: <15} | {3: <20} | {4: <7} | {5: <6} | {6}", key, profile.sid, profile.domain.unwrap_or_default(), profile.username.unwrap_or_default(), profile.roaming_configured, profile.loaded, profile.size.unwrap_or_default());
    }
    println!("Enter ID of profiles to keep: (example: 0,5,7,17)");
    let mut keep = HashSet::new();
    let mut buffer = String::new();
    stdin().read_line(&mut buffer)?;
    buffer.split(",").for_each(|s| {
        let usize =  s.trim().parse::<usize>();
        if let Ok(u) = usize {
            keep.insert(u);
        }
    });
    println!();
    println!();
    let mut sid_to_delete = HashSet::new();
    println!("=== Profiles to delete ===");
    println!("{0: <48} | {1: <15} | {2: <20} | {3: <7} | {4: <6} | {5}", "SID", "Domain", "Username", "Roaming", "Loaded", "Size");
    for (key, profile) in user_profiles.clone().into_iter().enumerate() {
        if !keep.contains(&key) {
            if profile.loaded {
                println!("{} can't be deleted, because profile is loaded", profile.sid.clone());
                continue;
            }
            sid_to_delete.insert(profile.sid.clone());
            println!("{0: <48} | {1: <15} | {2: <20} | {3: <7} | {4: <6} | {5}", profile.sid, profile.domain.unwrap_or_default(), profile.username.unwrap_or_default(), profile.roaming_configured, profile.loaded, profile.size.unwrap_or_default());
        }
    }
    println!("Do you want to continue? (y/n)");
    let mut buffer = String::new();
    stdin().read_line(&mut buffer)?;
    if buffer.trim().to_lowercase() == "y" {
        for sid in sid_to_delete {
            let result = delete_user_profile(&sid);
            if let Ok(_) = result {
                println!("Deleted profile {}", sid);
            } else {
                println!("Failed to delete profile {}", sid);
            }
        }
    } else {
        println!("Aborting!");
    }
    Ok(())
}
