use aes::Aes128;
use anyhow::{bail, Result};
use cfb_mode::Decryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use console::{style, Emoji};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

type Aes128Cfb = Decryptor<Aes128>;

#[derive(Debug, serde::Serialize)]
pub struct WeChatUserInfo {
    pub wxid: String,
    pub nickname: String,
}

pub fn find_wechat_data_dir_auto() -> Result<PathBuf> {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());
    let candidates = vec![
        PathBuf::from(&home).join("Documents").join("xwechat_files"),
        PathBuf::from(&home).join("xwechat_files"),
    ];
    for path in candidates {
        if path.exists() && path.is_dir() {
            return Ok(path);
        }
    }
    bail!("Automatic detection of WeChat data directory failed.");
}

pub fn find_wechat_data_dir() -> Result<PathBuf> {
    let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".to_string());

    let candidates = vec![
        PathBuf::from(&home).join("Documents").join("xwechat_files"),
        PathBuf::from(&home).join("xwechat_files"),
    ];

    for path in candidates {
        if path.exists() && path.is_dir() {
            return Ok(path);
        }
    }

    println!(
        "{} {}",
        Emoji("⚠️", "[-]"),
        style("Automatic detection of WeChat data directory failed.")
            .yellow()
            .bold()
    );
    println!("   Typically located at C:\\Users\\<User>\\Documents\\xwechat_files");
    print!("Please enter the absolute path to 'xwechat_files': ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input_path = input.trim();

    if input_path.is_empty() {
        bail!("No path entered, aborting!");
    }

    let custom_path = PathBuf::from(input_path);
    if custom_path.exists() && custom_path.is_dir() {
        Ok(custom_path)
    } else {
        bail!(
            "The entered path does not exist or is not a valid directory: {}",
            input_path
        );
    }
}

// Extract user unique IDs from MMKV cache
pub fn find_user_unique_ids() -> Result<Vec<String>> {
    let appdata = std::env::var("APPDATA").unwrap_or_else(|_| "C:\\".to_string());
    let kvcomm_dir = PathBuf::from(&appdata)
        .join("Tencent")
        .join("xwechat")
        .join("net")
        .join("kvcomm");

    if !kvcomm_dir.exists() {
        bail!("MMKV cache directory not found: {:?}", kvcomm_dir);
    }

    let mut uids = Vec::new();
    for entry in fs::read_dir(kvcomm_dir)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_string();

        let parts: Vec<&str> = file_name.split('_').collect();
        for part in parts {
            if part.len() > 6 && part.chars().all(|c| c.is_numeric()) && part != "0" {
                if !uids.contains(&part.to_string()) {
                    uids.push(part.to_string());
                }
                break;
            }
        }
    }

    if uids.is_empty() {
        bail!("No valid User Unique IDs (UID) found in MMKV directory!");
    }

    Ok(uids)
}


pub fn parse_global_config(root_path: &Path) -> Result<WeChatUserInfo> {
    let config_path = root_path
        .join("all_users")
        .join("config")
        .join("global_config");

    if !config_path.exists() {
        bail!("global_config file not found! ({:?})", config_path);
    }

    let full_data = fs::read(&config_path)?;
    if full_data.len() <= 4 {
        bail!("global_config file is corrupted or too small!");
    }

    // 解密逻辑
    let encrypted_data = &full_data[4..];
    // 直接用数组，更直观
    let key = b"xwechat_crypt_ke"; // 取前16位
    let iv = [0u8; 16];

    let cipher = Aes128Cfb::new_from_slices(key, &iv)
        .map_err(|e| anyhow::anyhow!("Failed to initialize decryptor: {}", e))?;

    let mut decrypted = encrypted_data.to_vec();
    cipher.decrypt(&mut decrypted);

    // 字段提取
    let wxid = extract_mmkv_string(&decrypted, "mmkv_key_user_name").unwrap_or_default();
    let nickname = extract_mmkv_string(&decrypted, "mmkv_key_nick_name").unwrap_or_default();

    if !wxid.is_empty() || !nickname.is_empty() {
        Ok(WeChatUserInfo { wxid, nickname })
    } else {
        bail!("Decryption successful, but failed to identify valid user information.");
    }
}

fn extract_mmkv_string(data: &[u8], key: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    memchr::memmem::find(data, key_bytes).and_then(|pos| {
        let mut offset = pos + key_bytes.len();

        while offset < data.len() && (data[offset] < 0x20 || data[offset] > 0x7E) {
            offset += 1;
        }

        let start = offset;
        while offset < data.len() && data[offset] >= 0x20 && data[offset] <= 0x7E {
            offset += 1;
        }

        if offset > start {
            String::from_utf8(data[start..offset].to_vec()).ok()
        } else {
            None
        }
    })
}