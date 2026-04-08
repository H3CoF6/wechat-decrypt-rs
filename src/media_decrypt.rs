use aes::Aes128;
use anyhow::Result;
use cipher::{BlockDecrypt, KeyInit};
use cliclack::log;
use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use jwalk::WalkDir;
use md5::{Digest, Md5};
use rayon::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, serde::Serialize)]
pub struct MediaKeys {
    pub xor_key: u8,
    pub aes_key_v2: Vec<u8>,
}

pub fn calculate_media_keys(wxid: &str, uids: &[String]) -> Vec<MediaKeys> {
    let mut keys_pool = Vec::new();
    for uid in uids {
        let xor_key = (uid.parse::<u32>().unwrap_or(0) & 0xFF) as u8;
        let hash_input = format!("{}{}", uid, wxid);
        let hash_hex = format!("{:x}", Md5::digest(hash_input.as_bytes()));
        let aes_key_v2 = hash_hex.as_bytes()[0..16].to_vec();

        keys_pool.push(MediaKeys {
            xor_key,
            aes_key_v2,
        });
    }
    keys_pool
}

pub fn decrypt_media(wxid_dir: &PathBuf, wxid: &str, uids: &[String]) -> Result<()> {
    log::step(format!("[*] {}", style("Building media key pool").bold()))?;

    let keys_pool = calculate_media_keys(wxid, uids);

    let mut dat_files = Vec::new();
    for entry in WalkDir::new(wxid_dir).into_iter().flatten() {
        if entry.file_type().is_file() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if name.ends_with(".dat") && name.len() >= 36 {
                let hash_part = &name[0..32];
                let is_hex = hash_part.chars().all(|c| c.is_ascii_hexdigit());

                let is_valid_format = if name.len() == 36 {
                    true // 纯 hash.dat
                } else {
                    // 检查第33位是否为下划线: hash_...
                    name.as_bytes().get(32) == Some(&b'_')
                };

                if is_hex && is_valid_format && !path.components().any(|c| c.as_os_str() == "db_storage") {
                    dat_files.push(path.to_path_buf());
                }
            }
        }
    }

    let total = dat_files.len();
    log::step(format!(
        "   Scan complete, found {} .dat encrypted resources.",
        style(total).cyan()
    ))?;

    if total == 0 {
        log::step("   No media resources found, skipping media decryption.")?;
        return Ok(());
    }

    log::step(format!(
        "[*] {}",
        style("Starting parallel media decryption").bold()
    ))?;

    let out_base = PathBuf::from("output").join(wxid).join("resource");
    fs::create_dir_all(&out_base)?;

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")?
            .progress_chars("#>-"),
    );

    let success_count = AtomicUsize::new(0);
    let aes_key_v1 = b"cfcd208495d565ef"; // Static AES key for V1 format

    dat_files.par_iter().for_each(|path| {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let hash = &name[0..32];
        let hash_prefix = &hash[0..2];

        let data = fs::read(path).unwrap_or_default();
        if data.is_empty() {
            pb.inc(1);
            return;
        }

        let mut decrypted: Option<(Vec<u8>, &'static str)> = None;

        for keys in &keys_pool {
            if data.starts_with(b"\x07\x08V1\x08\x07") {
                decrypted = decrypt_v1_v2(&data, aes_key_v1, keys.xor_key);
            } else if data.starts_with(b"\x07\x08V2\x08\x07") {
                decrypted = decrypt_v1_v2(&data, &keys.aes_key_v2, keys.xor_key);
            } else {
                decrypted = try_decrypt_v3(&data, keys.xor_key);
            }
            if decrypted.is_some() {
                break;
            }
        }

        if let Some((dec, ext)) = decrypted {
            let target_dir = out_base.join(hash_prefix);
            let _ = fs::create_dir_all(&target_dir);
            // 这里 ext 如果是 "wxgf"，则输出 hash.wxgf
            let out_file = target_dir.join(format!("{}.{}", hash, ext));
            if fs::write(&out_file, dec).is_ok() {
                success_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        pb.inc(1);
    });

    pb.finish_with_message("Media decryption completed!");

    let sc = success_count.load(Ordering::Relaxed);
    log::step(format!(
        "[+] Media decryption complete: {} success / {} total",
        style(sc).green().bold(),
        total
    ))?;
    log::step(format!(
        "   Output path: {}",
        style(out_base.display()).magenta()
    ))?;

    Ok(())
}

// --- WeChat 4.x V1/V2 (Hybrid AES + XOR) Decryption ---
pub fn decrypt_v1_v2(data: &[u8], aes_key: &[u8], xor_key: u8) -> Option<(Vec<u8>, &'static str)> {
    if data.len() < 16 {
        return None;
    }

    let aes_size_raw = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
    let xor_size = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
    let rest = &data[15..];

    let remainder = aes_size_raw % 16;
    let aes_size = if remainder == 0 {
        aes_size_raw
    } else {
        aes_size_raw + 16 - remainder
    };

    if rest.len() < aes_size {
        return None;
    }
    let aes_data = &rest[..aes_size];

    let cipher = Aes128::new_from_slice(&aes_key[..16]).ok()?;
    let mut buf = aes_data.to_vec();
    for chunk in buf.chunks_mut(16) {
        cipher.decrypt_block(cipher::generic_array::GenericArray::from_mut_slice(chunk));
    }

    if let Some(&pad_len) = buf.last() {
        let pad_usize = pad_len as usize;
        if pad_usize > 0 && pad_usize <= 16 && buf.len() >= pad_usize {
            let is_valid_padding = buf[buf.len() - pad_usize..]
                .iter()
                .all(|&b| b == pad_len);

            if is_valid_padding {
                buf.truncate(buf.len() - pad_usize);
            } else {
                log::info("Invalid padding detected, skipping truncate.").unwrap();
            }
        }
    }

    let mut raw_data = &rest[aes_size..];
    let mut xor_data: &[u8] = &[];

    if xor_size > 0 && raw_data.len() >= xor_size {
        let split_idx = raw_data.len() - xor_size;
        xor_data = &raw_data[split_idx..];
        raw_data = &raw_data[..split_idx];
    }

    let mut out = Vec::with_capacity(buf.len() + raw_data.len() + xor_data.len());
    out.extend_from_slice(&buf);
    out.extend_from_slice(raw_data);
    out.extend(xor_data.iter().map(|&b| b ^ xor_key));

    let ext = check_magic_plain(&out).unwrap_or("dat");
    Some((out, ext))
}

// --- WeChat V3 (XOR Only) Decryption & Magic Sniffing ---
pub fn try_decrypt_v3(data: &[u8], uid_xor_key: u8) -> Option<(Vec<u8>, &'static str)> {
    if data.is_empty() {
        return None;
    }

    // 1. Try with uid_xor_key
    if let Some(ext) = check_xor_with_key(data, uid_xor_key) {
        let dec = data.iter().map(|&b| b ^ uid_xor_key).collect();
        return Some((dec, ext));
    }

    // 2. Try all possible keys (brute force)
    for key in 0..=255 {
        if key == uid_xor_key {
            continue;
        }
        if let Some(ext) = check_xor_with_key(data, key) {
            let dec = data.iter().map(|&b| b ^ key).collect();
            return Some((dec, ext));
        }
    }

    None
}

fn check_xor_with_key(data: &[u8], key: u8) -> Option<&'static str> {
    let mut prefix = [0u8; 32];
    let len = data.len().min(32);
    for i in 0..len {
        prefix[i] = data[i] ^ key;
    }
    check_magic_plain(&prefix[..len])
}

pub fn check_magic_plain(data: &[u8]) -> Option<&'static str> {
    // 优先匹配 wxgf
    if data.starts_with(b"wxgf") {
        return Some("wxgf");
    }
    infer::get(data).map(|kind| kind.extension())
}