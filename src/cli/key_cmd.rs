//! `wx key` — 密钥管理（extract / list / set）

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::collections::BTreeMap;
use crate::config;
use crate::scanner::{self, KeyEntry};

pub fn cmd_key_list(json: bool, show_secrets: bool) -> Result<()> {
    let cfg = config::load_config().context("Run wx init first")?;
    let content = std::fs::read_to_string(&cfg.keys_file)
        .with_context(|| format!("Reading {}", cfg.keys_file.display()))?;
    let v: serde_json::Value = serde_json::from_str(&content)?;
    let mut known = Vec::new();
    let mut rows = Vec::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k.starts_with('_') {
                continue;
            }
            let enc = val
                .as_str()
                .map(|s| s.to_string())
                .or_else(|| {
                    val.get("enc_key")
                        .and_then(|e| e.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_default();
            if enc.is_empty() {
                continue;
            }
            let preview = format!("{}…", &enc[..enc.len().min(12)]);
            known.push(KeyEntry {
                db_name: k.replace('\\', "/"),
                enc_key: enc.clone(),
                salt: String::new(),
            });
            if show_secrets {
                rows.push(json!({
                    "db": k,
                    "enc_key": enc,
                    "preview": preview,
                }));
            } else {
                rows.push(json!({
                    "db": k,
                    "preview": preview,
                }));
            }
        }
    }
    rows.sort_by(|a, b| {
        a["db"]
            .as_str()
            .unwrap_or("")
            .cmp(b["db"].as_str().unwrap_or(""))
    });

    let missing = scanner::list_missing_encrypted_dbs(&cfg.db_dir, &known);
    let critical: Vec<_> = missing
        .iter()
        .filter(|m| scanner::is_critical_missing_db(&m.rel))
        .cloned()
        .collect();
    let optional: Vec<_> = missing
        .iter()
        .filter(|m| !scanner::is_critical_missing_db(&m.rel))
        .cloned()
        .collect();

    if json {
        let miss_json: Vec<_> = missing
            .iter()
            .map(|m| {
                json!({
                    "db": m.rel,
                    "size": m.size,
                    "size_human": scanner::format_db_size(m.size),
                    "critical": scanner::is_critical_missing_db(&m.rel),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "count": rows.len(),
                "keys": rows,
                "missing": miss_json,
                "critical_missing": critical.len(),
                "optional_missing": optional.len(),
            }))?
        );
    } else {
        println!("Keys file: {}", cfg.keys_file.display());
        println!("Data directory: {}", cfg.db_dir.display());
        println!("{} keys total", rows.len());
        for r in &rows {
            println!(
                "  {}  {}",
                r["db"].as_str().unwrap_or(""),
                r["preview"].as_str().unwrap_or("")
            );
        }
        if !show_secrets {
            println!("(full enc_key requires --show-secrets)");
        }
        if !critical.is_empty() {
            println!(
                "\n✗ {} critical missing (affects chat completeness):",
                critical.len()
            );
            for m in &critical {
                println!(
                    "  · {} ({})",
                    m.rel,
                    scanner::format_db_size(m.size)
                );
            }
            println!(
                "To fill in: {}\n\
                 While waiting, open the relevant chats in WeChat.",
                config::RECOMMENDED_KEY_EXTRACT
            );
        } else if !missing.is_empty() {
            println!("\n✓ All critical chat shard keys present");
        } else {
            println!("\n✓ All encrypted DBs on disk are covered");
        }
        if !optional.is_empty() {
            println!("{} auxiliary/optional missing:", optional.len());
            for m in optional.iter().take(6) {
                println!(
                    "  · {} ({})",
                    m.rel,
                    scanner::format_db_size(m.size)
                );
            }
        }
    }
    Ok(())
}

pub fn cmd_key_set(db_name: &str, enc_key: &str) -> Result<()> {
    let key = enc_key.trim().to_lowercase();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("enc_key must be 64 hex characters");
    }
    let cfg = config::load_config().context("Run wx init first")?;
    let mut map: BTreeMap<String, serde_json::Value> = if cfg.keys_file.exists() {
        let content = std::fs::read_to_string(&cfg.keys_file)?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let rel = db_name.replace('\\', "/");
    // validate if file exists
    let path = cfg.db_dir.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR));
    if path.exists() {
        if let Some(raw) = scanner::decode_key_hex_pub(&key) {
            if !crate::crypto::validate_raw_key_for_db(&path, &raw) {
                bail!("Key cannot decrypt {}; check the hex is correct", rel);
            }
        }
    }
    map.insert(rel.clone(), json!({ "enc_key": key }));
    if let Some(parent) = cfg.keys_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cfg.keys_file, serde_json::to_string_pretty(&map)?)?;
    println!("Key written: {} → {}", rel, cfg.keys_file.display());
    // try hot-reload（会 invalidate 解密缓存）
    match super::transport::send(crate::ipc::Request::ReloadConfig) {
        Ok(resp) if resp.ok => {
            println!(
                "Hot-reloaded daemon config (keys={})",
                resp.data
                    .get("keys")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );
        }
        Ok(resp) => {
            eprintln!(
                "daemon hot reload failed: {}; run wx daemon restart",
                resp.error.unwrap_or_default()
            );
        }
        Err(e) => {
            eprintln!("daemon not running or unreachable ({}); new keys load on next start", e);
        }
    }
    Ok(())
}

pub fn cmd_key_extract(hook_seconds: Option<u64>) -> Result<()> {
    println!(
        "Extracting keys (memory scan + optional LLDB hook; recommended: {})…",
        config::RECOMMENDED_KEY_EXTRACT
    );
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "Warning: use {} so task_for_pid can read process memory",
            config::RECOMMENDED_KEY_EXTRACT
        );
    }
    super::init::cmd_init(true, hook_seconds)
}
