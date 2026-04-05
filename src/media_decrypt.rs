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

struct MediaKeys {
    xor_key: u8,
    aes_key_v2: Vec<u8>,
}

pub fn decrypt_media(wxid_dir: &PathBuf, wxid: &str, uids: &[String]) -> Result<()> {
    log::step(format!("[*] {}", style("Building media key pool").bold()))?;

    let mut keys_pool = Vec::new();
    for uid in uids {
        let xor_key = (uid.parse::<u32>().unwrap_or(0) & 0xFF) as u8;
        let hash_input = format!("{}{}", uid, wxid);
        let hash_hex = format!("{:x}", Md5::digest(hash_input.as_bytes()));
        let aes_key_v2 = hash_hex[0..16].as_bytes().to_vec();

        keys_pool.push(MediaKeys {
            xor_key,
            aes_key_v2,
        });
    }

    let mut dat_files = Vec::new();
    for entry in WalkDir::new(wxid_dir).into_iter().flatten() {
        if entry.file_type().is_file() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("dat") {
                if !path.components().any(|c| c.as_os_str() == "db_storage") {
                    dat_files.push(path);
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

    let out_dir = PathBuf::from("output").join(wxid).join("media");
    fs::create_dir_all(&out_dir)?;

    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")?
            .progress_chars("#>-"),
    );

    let success_count = AtomicUsize::new(0);
    let aes_key_v1 = b"cfcd208495d565ef"; // Static AES key for V1 format

    dat_files.par_iter().for_each(|path| {
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
            let stem = path.file_stem().unwrap().to_string_lossy();
            let out_name = format!("{}.{}", stem, ext);
            let out_file = out_dir.join(&out_name);
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
        style(out_dir.display()).magenta()
    ))?;

    Ok(())
}

// --- WeChat 4.x V1/V2 (Hybrid AES + XOR) Decryption ---
fn decrypt_v1_v2(data: &[u8], aes_key: &[u8], xor_key: u8) -> Option<(Vec<u8>, &'static str)> {
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
        if pad_len > 0 && pad_len <= 16 {
            buf.truncate(buf.len() - pad_len as usize);
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
fn try_decrypt_v3(data: &[u8], uid_xor_key: u8) -> Option<(Vec<u8>, &'static str)> {
    if data.is_empty() {
        return None;
    }

    let magics = [
        (b"\xFF\xD8\xFF".as_slice(), "jpg"),
        (b"\x89PNG\r\n\x1a\n".as_slice(), "png"),
        (b"GIF89a".as_slice(), "gif"),
        (b"GIF87a".as_slice(), "gif"),
        (b"RIFF".as_slice(), "webp"),
        (b"wxgf".as_slice(), "dat"),
        (b"\x00\x00\x00\x1cftyp".as_slice(), "mp4"),
        (b"\x00\x00\x00\x18ftyp".as_slice(), "mp4"),
        (b"\x00\x00\x00\x20ftyp".as_slice(), "mp4"),
    ];

    let first_byte = data[0] ^ uid_xor_key;
    for (magic, ext) in &magics {
        if first_byte == magic[0] {
            let mut ok = true;
            for i in 1..magic.len().min(data.len()) {
                if data[i] ^ uid_xor_key != magic[i] {
                    ok = false;
                    break;
                }
            }
            if ok {
                let dec = data.iter().map(|&b| b ^ uid_xor_key).collect();
                return Some((dec, ext));
            }
        }
    }

    for (magic, ext) in &magics {
        let guessed_key = data[0] ^ magic[0];
        let mut ok = true;
        for i in 1..magic.len().min(data.len()) {
            if data[i] ^ guessed_key != magic[i] {
                ok = false;
                break;
            }
        }
        if ok {
            let dec = data.iter().map(|&b| b ^ guessed_key).collect();
            return Some((dec, ext));
        }
    }

    None
}

fn check_magic_plain(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\xFF\xD8\xFF") {
        Some("jpg")
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if data.starts_with(b"GIF8") {
        Some("gif")
    } else if data.starts_with(b"RIFF") && data.len() >= 12 && &data[8..12] == b"WEBP" {
        Some("webp")
    } else if data.len() >= 8 && &data[4..8] == b"ftyp" {
        Some("mp4")
    } else {
        Some("wxgf")
    }
}
