pub mod config;
pub mod db_decrypt;
pub mod media_decrypt;
pub mod sys;

use serde_json::json;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::collections::HashMap;

fn string_to_ptr(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

pub struct WxDbContext {
    pub pid: u32,
    pub wxid: String,
    pub db_map: HashMap<String, (PathBuf, String, String)>,
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

    let tasks = media_decrypt::scan_media_files(&in_path);

    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let success_count = AtomicUsize::new(0);
    let aes_key_v1 = b"cfcd208495d565ef";

    tasks.par_iter().for_each(|task| {
        let data = std::fs::read(&task.path).unwrap_or_default();
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
            let out_name = format!("{}.{}", task.hash, ext);
            let out_file = out_path.join(&out_name);
            if std::fs::write(&out_file, dec).is_ok() {
                success_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let sc = success_count.load(Ordering::Relaxed);
    string_to_ptr(
        json!({
            "total": tasks.len(),
            "success": sc,
        })
            .to_string(),
    )
}
#[no_mangle]
pub extern "C" fn init_db_context() -> *mut WxDbContext {
    let pid = match unsafe { sys::find_wechat_pid() } {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[-] 获取微信 PID 失败: {}", e);
            return std::ptr::null_mut();
        }
    };

    let data_dir = match config::find_wechat_data_dir_auto() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[-] 获取微信数据目录失败: {}", e);
            return std::ptr::null_mut();
        }
    };

    let user_info = match config::parse_global_config(&data_dir) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("[-] 解析 global_config 失败: {}", e);
            return std::ptr::null_mut();
        }
    };
    let wxid = user_info.wxid;

    let mut wxid_dir = None;
    if let Ok(entries) = std::fs::read_dir(&data_dir) {
        for entry in entries.flatten() {
            let folder_name = entry.file_name().to_string_lossy().to_string();
            if folder_name.starts_with(&format!("{}_", wxid)) || folder_name == wxid {
                wxid_dir = Some(entry.path());
                break;
            }
        }
    }

    let wxid_dir = match wxid_dir {
        Some(dir) => dir,
        None => {
            eprintln!("[-] 未找到 wxid ({}) 对应的数据目录", wxid);
            return std::ptr::null_mut();
        }
    };

    let mut db_storage = wxid_dir.join("db_storage");
    if !db_storage.exists() {
        db_storage = wxid_dir.join("msg").join("db_storage");
    }

    if !db_storage.exists() {
        eprintln!("[-] 找不到 db_storage 目录: {:?}", db_storage);
        return std::ptr::null_mut();
    }

    let db_map = db_decrypt::collect_dbs(&db_storage);
    if db_map.is_empty() {
        eprintln!("[-] 在 {:?} 下未找到有效的微信数据库文件", db_storage);
        return std::ptr::null_mut();
    }

    let results = match unsafe { db_decrypt::scan_memory(pid, &db_map) } {
        Ok(res) => res,
        Err(e) => {
            eprintln!("[-] 内存扫描密钥失败: {}", e);
            return std::ptr::null_mut();
        }
    };

    let mut context = WxDbContext {
        pid,
        wxid,
        db_map: HashMap::new(),
    };

    for (salt, raw_key) in results {
        if let Some(infos) = db_map.get(&salt) {
            let key_hex = hex::encode(&raw_key).to_lowercase();
            for info in infos {
                context.db_map.insert(
                    info.name.clone(),
                    (info.filepath.clone(), key_hex.clone(), salt.clone()),
                );
            }
        }
    }

    Box::into_raw(Box::new(context))
}


#[no_mangle]
/// Frees a string allocated by Rust and passed to C.
///
/// # Safety
///
/// The caller must ensure that the pointer was originally created by `CString::into_raw`
/// and has not been freed yet.
pub unsafe extern "C" fn free_db_context(ptr: *mut WxDbContext) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr);
    }
}

#[no_mangle]
/// Frees a string allocated by Rust and passed to C.
///
/// # Safety
///
/// The caller must ensure that the pointer was originally created by `CString::into_raw`
/// and has not been freed yet.
pub unsafe extern "C" fn exec_sql(
    ctx: *mut WxDbContext,
    db_name: *const c_char,
    sql: *const c_char,
) -> *mut c_char {
    if ctx.is_null() {
        return string_to_ptr(json!({"error": "Context pointer is null"}).to_string());
    }

    let db_name_str = match ptr_to_string(db_name) {
        Some(s) => s,
        None => return string_to_ptr(json!({"error": "Invalid db_name pointer"}).to_string()),
    };

    let sql_str = match ptr_to_string(sql) {
        Some(s) => s,
        None => return string_to_ptr(json!({"error": "Invalid sql pointer"}).to_string()),
    };

    let context = unsafe { &*ctx };

    // 查找有没有对应数据库的密钥
    let (db_path, key_hex, salt_hex) = match context.db_map.get(&db_name_str) {
        Some(data) => data,
        None => {
            return string_to_ptr(
                json!({
                    "error": format!("Database '{}' not found in decrypted context", db_name_str)
                })
                    .to_string(),
            )
        }
    };

    let conn = match rusqlite::Connection::open(db_path) {
        Ok(c) => c,
        Err(e) => {
            return string_to_ptr(json!({"error": format!("Failed to open DB: {}", e)}).to_string())
        }
    };

    // 注入微信加密配置并跳过主密钥派生
    let pragma_key = format!("PRAGMA key = \"x'{}{}'\";", key_hex, salt_hex);
    let setup_sql = format!(
        "
        {};
        PRAGMA cipher_page_size = 4096;
        PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
        PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
        ",
        pragma_key
    );

    if let Err(e) = conn.execute_batch(&setup_sql) {
        return string_to_ptr(json!({"error": format!("Crypto setup failed: {}", e)}).to_string());
    }

    let sql_upper = sql_str.trim().to_uppercase();
    if sql_upper.starts_with("SELECT") || sql_upper.starts_with("PRAGMA") {
        let mut stmt = match conn.prepare(&sql_str) {
            Ok(s) => s,
            Err(e) => {
                return string_to_ptr(json!({"error": format!("Prepare failed: {}", e)}).to_string())
            }
        };

        let column_names: Vec<String> =
            stmt.column_names().into_iter().map(String::from).collect();

        let rows_iter = match stmt.query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, name) in column_names.iter().enumerate() {
                let val_ref = match row.get_ref(i) {
                    Ok(v) => v,
                    Err(_) => rusqlite::types::ValueRef::Null,
                };
                // 转换 SQLite 数据类型到 JSON 数据类型
                let json_val = match val_ref {
                    rusqlite::types::ValueRef::Null => serde_json::Value::Null,
                    rusqlite::types::ValueRef::Integer(i) => json!(i),
                    rusqlite::types::ValueRef::Real(f) => json!(f),
                    rusqlite::types::ValueRef::Text(t) => {
                        json!(String::from_utf8_lossy(t))
                    }
                    rusqlite::types::ValueRef::Blob(b) => json!(hex::encode(b)),
                };
                map.insert(name.clone(), json_val);
            }
            Ok(serde_json::Value::Object(map))
        }) {
            Ok(r) => r,
            Err(e) => {
                return string_to_ptr(json!({"error": format!("Query failed: {}", e)}).to_string())
            }
        };

        let mut results = Vec::new();
        for r in rows_iter.flatten() {
            results.push(r);
        }

        string_to_ptr(json!({"success": true, "data": results}).to_string())
    } else {
        match conn.execute(&sql_str, []) {
            Ok(affected) => {
                string_to_ptr(json!({"success": true, "affected_rows": affected}).to_string())
            }
            Err(e) => {
                string_to_ptr(json!({"error": format!("Execute failed: {}", e)}).to_string())
            }
        }
    }
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
