pub mod config;
pub mod db_decrypt;
pub mod media_decrypt;
pub mod sys;

use serde_json::json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;

fn string_to_ptr(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

fn ptr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { Some(CStr::from_ptr(ptr).to_string_lossy().into_owned()) }
}

#[no_mangle]
pub extern "C" fn get_wechat_state() -> *mut c_char {
    let mut state = json!({});

    let pid = match unsafe { sys::find_wechat_pid() } {
        Ok(p) => p,
        Err(e) => {
            state["error"] = json!(e.to_string());
            return string_to_ptr(state.to_string());
        }
    };
    state["pid"] = json!(pid);

    let data_dir = match config::find_wechat_data_dir_auto() {
        Ok(d) => d,
        Err(e) => {
            state["error"] = json!(e.to_string());
            return string_to_ptr(state.to_string());
        }
    };
    state["data_dir"] = json!(data_dir.to_string_lossy().to_string());

    let user_info = match config::parse_global_config(&data_dir) {
        Ok(info) => info,
        Err(e) => {
            state["error"] = json!(e.to_string());
            return string_to_ptr(state.to_string());
        }
    };
    state["wxid"] = json!(user_info.wxid);
    state["nickname"] = json!(user_info.nickname);

    if let Ok(uids) = config::find_user_unique_ids() {
        state["uids"] = json!(uids);
    }

    string_to_ptr(state.to_string())
}

#[no_mangle]
pub extern "C" fn get_db_keys(pid: u32, db_dir: *const c_char) -> *mut c_char {
    let dir_str = match ptr_to_string(db_dir) {
        Some(s) => s,
        None => return string_to_ptr(json!({"error": "Invalid db_dir pointer"}).to_string()),
    };

    let path = PathBuf::from(dir_str);
    let db_map = db_decrypt::collect_dbs(&path);
    if db_map.is_empty() {
        return string_to_ptr(json!({"error": "No valid databases found in dir"}).to_string());
    }

    let results = match unsafe { db_decrypt::scan_memory(pid, &db_map) } {
        Ok(res) => res,
        Err(e) => return string_to_ptr(json!({"error": e.to_string()}).to_string()),
    };

    let mut out = Vec::new();
    for (salt, raw_key) in results {
        if let Some(infos) = db_map.get(&salt) {
            for info in infos {
                out.push(json!({
                    "name": info.name,
                    "filepath": info.filepath.to_string_lossy().to_string(),
                    "salt": salt,
                    "key": hex::encode(&raw_key)
                }));
            }
        }
    }

    string_to_ptr(json!({ "keys": out }).to_string())
}

#[no_mangle]
pub extern "C" fn get_image_keys() -> *mut c_char {
    let data_dir = match config::find_wechat_data_dir_auto() {
        Ok(d) => d,
        Err(e) => return string_to_ptr(json!({"error": e.to_string()}).to_string()),
    };

    let user_info = match config::parse_global_config(&data_dir) {
        Ok(info) => info,
        Err(e) => return string_to_ptr(json!({"error": e.to_string()}).to_string()),
    };

    let uids = match config::find_user_unique_ids() {
        Ok(u) => u,
        Err(e) => return string_to_ptr(json!({"error": e.to_string()}).to_string()),
    };

    let keys = media_decrypt::calculate_media_keys(&user_info.wxid, &uids);

    let keys_json: Vec<_> = keys
        .iter()
        .map(|k| {
            json!({
                "xor_key": k.xor_key,
                "aes_key_v2": hex::encode(&k.aes_key_v2)
            })
        })
        .collect();

    string_to_ptr(json!({ "keys": keys_json }).to_string())
}

#[no_mangle]
pub extern "C" fn batch_decrypt_images(
    aes_key_hex: *const c_char,
    xor_key: u8,
    account_dir: *const c_char,
    out_dir: *const c_char,
) -> *mut c_char {
    let aes_hex_str = match ptr_to_string(aes_key_hex) {
        Some(s) => s,
        None => return string_to_ptr(json!({"error": "Invalid aes_key pointer"}).to_string()),
    };

    let aes_key = match hex::decode(&aes_hex_str) {
        Ok(k) => k,
        Err(e) => {
            return string_to_ptr(
                json!({"error": format!("Invalid AES hex: {}", e)}).to_string(),
            )
        }
    };

    let acc_dir_str = match ptr_to_string(account_dir) {
        Some(s) => s,
        None => {
            return string_to_ptr(json!({"error": "Invalid account_dir pointer"}).to_string())
        }
    };
    let out_dir_str = match ptr_to_string(out_dir) {
        Some(s) => s,
        None => return string_to_ptr(json!({"error": "Invalid out_dir pointer"}).to_string()),
    };

    let in_path = PathBuf::from(&acc_dir_str);
    let out_path = PathBuf::from(&out_dir_str);

    if let Err(e) = std::fs::create_dir_all(&out_path) {
        return string_to_ptr(
            json!({"error": format!("Failed to create output dir: {}", e)}).to_string(),
        );
    }

    use jwalk::WalkDir;
    let mut dat_files = Vec::new();
    for entry in WalkDir::new(&in_path).into_iter().flatten() {
        if entry.file_type().is_file() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("dat")
                && !path.components().any(|c| c.as_os_str() == "db_storage")
            {
                dat_files.push(path);
            }
        }
    }

    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let success_count = AtomicUsize::new(0);
    let aes_key_v1 = b"cfcd208495d565ef";

    dat_files.par_iter().for_each(|path| {
        let data = std::fs::read(path).unwrap_or_default();
        if data.is_empty() {
            return;
        }

        let decrypted: Option<(Vec<u8>, &'static str)>;

        if data.starts_with(b"\x07\x08V1\x08\x07") {
            decrypted = media_decrypt::decrypt_v1_v2(&data, aes_key_v1, xor_key);
        } else if data.starts_with(b"\x07\x08V2\x08\x07") {
            decrypted = media_decrypt::decrypt_v1_v2(&data, &aes_key, xor_key);
        } else {
            decrypted = media_decrypt::try_decrypt_v3(&data, xor_key);
        }

        if let Some((dec, ext)) = decrypted {
            let stem = path.file_stem().unwrap().to_string_lossy();
            let out_name = format!("{}.{}", stem, ext);
            let out_file = out_path.join(&out_name);
            if std::fs::write(&out_file, dec).is_ok() {
                success_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let sc = success_count.load(Ordering::Relaxed);
    string_to_ptr(
        json!({
            "total": dat_files.len(),
            "success": sc,
        })
        .to_string(),
    )
}

#[no_mangle]
/// Frees a string allocated by Rust and passed to C.
///
/// # Safety
///
/// The caller must ensure that the pointer was originally created by `CString::into_raw`
/// and has not been freed yet.
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}
