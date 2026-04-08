use aes::Aes256;
use anyhow::{bail, Result};
use cbc::Decryptor;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use cliclack::log;
use console::{style, Emoji};
use hmac::{Hmac, Mac};
use indicatif::{ProgressBar, ProgressStyle};
use jwalk::WalkDir;
use pbkdf2::pbkdf2_hmac;
use rayon::prelude::*;
use sha2::Sha512;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

type Aes256CbcDec = Decryptor<Aes256>;

// --- WeChat 4.x Cryptography Constants ---
const PAGE_SIZE: usize = 4096;
const SALT_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const IV_SIZE: usize = 16;
const HMAC_SIZE: usize = 64; // SHA-512
const RESERVE_SIZE: usize = 80; // 16 (IV) + 64 (HMAC) = 80
const MAX_REGION: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DbInfo {
    pub filepath: PathBuf,
    pub name: String,
    #[serde(skip)]
    pub page1: Vec<u8>,
}

// --- Core Cryptography Logic ---

fn derive_mac_key(raw_key: &[u8], salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut mac_salt = [0u8; SALT_SIZE];
    for i in 0..SALT_SIZE {
        mac_salt[i] = salt[i] ^ 0x3A;
    }
    let mut mac_key = [0u8; KEY_SIZE];
    pbkdf2_hmac::<Sha512>(raw_key, &mac_salt, 2, &mut mac_key);
    mac_key
}

fn verify_page1_hmac(page1: &[u8], raw_key: &[u8]) -> bool {
    let salt = &page1[..SALT_SIZE];
    let mac_key = derive_mac_key(raw_key, salt);

    let data_end = PAGE_SIZE - RESERVE_SIZE + IV_SIZE;
    let mut mac = Hmac::<Sha512>::new_from_slice(&mac_key).unwrap();
    mac.update(&page1[SALT_SIZE..data_end]);
    mac.update(&1u32.to_le_bytes()); // pgno = 1

    let computed = mac.finalize().into_bytes();
    let stored = &page1[PAGE_SIZE - HMAC_SIZE..PAGE_SIZE];

    let mut diff = 0;
    for i in 0..HMAC_SIZE {
        diff |= computed[i] ^ stored[i];
    }
    diff == 0
}

fn decrypt_page(page_data: &[u8], raw_key: &[u8], pgno: u32) -> Result<Vec<u8>> {
    let offset = if pgno == 1 { SALT_SIZE } else { 0 };
    let iv = &page_data[PAGE_SIZE - RESERVE_SIZE..PAGE_SIZE - RESERVE_SIZE + IV_SIZE];
    let encrypted = &page_data[offset..PAGE_SIZE - RESERVE_SIZE];

    let cipher = Aes256CbcDec::new(raw_key.into(), iv.into());
    let mut buf = encrypted.to_vec();
    cipher
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| anyhow::anyhow!("AES decryption failed: {}", e))?;

    let mut out = Vec::with_capacity(PAGE_SIZE);
    if pgno == 1 {
        // Rebuild SQLite file header
        out.extend_from_slice(b"SQLite format 3\0");
        out.extend_from_slice(&buf);
    } else {
        out.extend_from_slice(&buf);
    }
    out.resize(PAGE_SIZE, 0);
    Ok(out)
}

fn decrypt_db(input: &Path, output: &Path, raw_key: &[u8]) -> Result<()> {
    let file_data = fs::read(input)?;
    if file_data.len() < PAGE_SIZE {
        bail!("File too small");
    }

    let total_pages = file_data.len() / PAGE_SIZE;
    let mut out_data = Vec::with_capacity(total_pages * PAGE_SIZE);

    for pgno in 1..=(total_pages as u32) {
        let offset = ((pgno - 1) as usize) * PAGE_SIZE;
        let page_raw = &file_data[offset..offset + PAGE_SIZE];
        let dec = decrypt_page(page_raw, raw_key, pgno)?;
        out_data.extend(dec);
    }

    fs::write(output, out_data)?;
    Ok(())
}

// --- Memory Scanning and Key Extraction ---

pub fn collect_dbs(db_storage: &Path) -> HashMap<String, Vec<DbInfo>> {
    let mut pa_map: HashMap<String, Vec<DbInfo>> = HashMap::new();

    for entry in WalkDir::new(db_storage).into_iter().flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("db") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name == "key_info.db" {
                continue;
            }

            if let Ok(mut f) = fs::File::open(&path) {
                use std::io::Read;
                let mut page1 = vec![0u8; PAGE_SIZE];
                if f.read_exact(&mut page1).is_ok() {
                    let salt_hex = hex::encode(&page1[0..SALT_SIZE]);
                    pa_map.entry(salt_hex).or_default().push(DbInfo {
                        filepath: path,
                        name,
                        page1,
                    });
                }
            }
        }
    }
    pa_map
}

/// Scans the memory of a process to find database decryption keys.
///
/// # Safety
///
/// This function is unsafe because it performs raw memory reading from another process
/// using Windows APIs. The caller must ensure that the provided `pid` is valid and
/// that the process has not been terminated during the scan.
pub unsafe fn scan_memory(
    pid: u32,
    db_map: &HashMap<String, Vec<DbInfo>>,
) -> Result<HashMap<String, Vec<u8>>> {
    let handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)?;
    let mut results = HashMap::new();
    let mut remaining_salts: HashSet<String> = db_map.keys().cloned().collect();

    let mut addr = 0usize;
    let mut mbi = MEMORY_BASIC_INFORMATION::default();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")?
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );

    let readable_prots: [u32; 8] = [0x02, 0x04, 0x06, 0x08, 0x20, 0x40, 0x60, 0x80];
    let mut buf: Vec<u8> = Vec::new();
    let mut scan_count = 0;

    while VirtualQueryEx(
        handle,
        Some(addr as _),
        &mut mbi,
        size_of::<MEMORY_BASIC_INFORMATION>(),
    ) != 0
    {
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let prot = mbi.Protect.0 & 0xFF;

        if mbi.State == MEM_COMMIT
            && size > 0
            && size <= MAX_REGION
            && readable_prots.contains(&prot)
        {
            if buf.len() < size {
                buf.resize(size, 0);
            }

            let mut bytes_read = 0;
            if windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                handle,
                base as _,
                buf.as_mut_ptr() as _,
                size,
                Some(&mut bytes_read),
            )
            .is_ok()
                && bytes_read > 0
            {
                let valid_data = &buf[..bytes_read];
                scan_count += 1;

                if scan_count % 50 == 0 {
                    pb.set_message(format!(
                        "Matching database keys: 0x{:X} (Remaining: {})",
                        base,
                        remaining_salts.len()
                    ));
                }

                let mut offset = 0;
                while let Some(pos) = memchr::memmem::find(&valid_data[offset..], b"x'") {
                    let idx = offset + pos;
                    offset = idx + 2;

                    if idx + 2 + 96 < bytes_read && valid_data[idx + 2 + 96] == b'\'' {
                        let hex_bytes = &valid_data[idx + 2..idx + 2 + 96];
                        if hex_bytes.iter().all(|&c| c.is_ascii_hexdigit()) {
                            let key_hex = String::from_utf8_lossy(&hex_bytes[0..64]).to_lowercase();
                            let salt_hex =
                                String::from_utf8_lossy(&hex_bytes[64..96]).to_lowercase();

                            if remaining_salts.contains(&salt_hex) {
                                if let Ok(raw_key) = hex::decode(&key_hex) {
                                    let db_info = &db_map[&salt_hex][0];
                                    if verify_page1_hmac(&db_info.page1, &raw_key) {
                                        results.insert(salt_hex.clone(), raw_key);
                                        remaining_salts.remove(&salt_hex);
                                        if remaining_salts.is_empty() {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if remaining_salts.is_empty() {
                    break;
                }
            }
        }
        addr = base + size;
        if addr >= 0x7FFFFFFFFFFF {
            break;
        }
    }

    pb.finish_with_message("Memory scan completed!");
    CloseHandle(handle)?;
    Ok(results)
}

pub fn dump_and_decrypt(pid: u32, db_storage: &Path, wxid: &str) -> Result<()> {
    log::step(format!(
        "[*] {}",
        style("Building local database list").bold()
    ))?;
    let db_map = collect_dbs(db_storage);
    let total_dbs: usize = db_map.values().map(|v| v.len()).sum();
    log::step(format!(
        "   Scan complete, found {} valid database files.",
        style(total_dbs).cyan()
    ))?;

    if total_dbs == 0 {
        bail!("No decryptable databases found!");
    }

    log::step(format!(
        "[*] {}",
        style("Extracting decryption keys from memory").bold()
    ))?;
    let keys_map = unsafe { scan_memory(pid, &db_map)? };
    log::step(format!(
        "   Extraction complete, retrieved {}/{} keys.",
        style(keys_map.len()).green(),
        style(db_map.len()).cyan()
    ))?;

    if keys_map.is_empty() {
        bail!("No matching database keys found in memory. Ensure WeChat is logged in!");
    }

    log::step(format!(
        "[*] {}",
        style("Starting parallel database decryption").bold()
    ))?;

    let out_dir = PathBuf::from("output").join(wxid).join("databases");
    fs::create_dir_all(&out_dir)?;

    let pb = ProgressBar::new(total_dbs as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")?
            .progress_chars("#>-"),
    );

    let success_count = Mutex::new(0);
    let failed_names = Mutex::new(Vec::new());

    db_map.par_iter().for_each(|(salt, infos)| {
        if let Some(raw_key) = keys_map.get(salt) {
            for info in infos {
                let out_path = out_dir.join(&info.name);
                match decrypt_db(&info.filepath, &out_path, raw_key) {
                    Ok(_) => {
                        *success_count.lock().unwrap() += 1;
                    }
                    Err(_) => {
                        failed_names.lock().unwrap().push(info.name.clone());
                    }
                }
                pb.inc(1);
            }
        } else {
            for info in infos {
                failed_names
                    .lock()
                    .unwrap()
                    .push(format!("{} (Key not found)", info.name));
                pb.inc(1);
            }
        }
    });

    pb.finish_with_message("Database decryption completed!");

    let sc = *success_count.lock().unwrap();
    let fails = failed_names.lock().unwrap();

    log::step(format!(
        "{}",
        style("--------------------------------------------------").dim()
    ))?;
    if sc > 0 {
        log::step(format!(
            "[+] Decryption complete: {} success / {} total",
            style(sc).green().bold(),
            total_dbs
        ))?;
        log::step(format!(
            "   Output path: {}",
            style(out_dir.display()).magenta()
        ))?;
    } else {
        bail!("All database decryptions failed!");
    }

    if !fails.is_empty() {
        log::step(format!(
            "\n{} Failed list ({} total):",
            Emoji("⚠️", "[-]"),
            fails.len()
        ))?;
        for name in fails.iter().take(10) {
            log::step(format!("   - {}", style(name).red()))?;
        }
        if fails.len() > 10 {
            log::step(format!("   ... and {} more files", fails.len() - 10))?;
        }
    }

    Ok(())
}
