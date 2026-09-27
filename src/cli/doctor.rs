//! `wx doctor` — 环境 / 密钥 / 分片健康检查（多数项无需 daemon）

use anyhow::Result;
use serde_json::json;
use std::path::Path;
use std::process::Command;

use crate::config;
use crate::scanner::{self, KeyEntry};

#[derive(Debug)]
struct Check {
    name: String,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

pub fn cmd_doctor(json: bool, fix: bool) -> Result<()> {
    let checks = run_checks();
    if json {
        let arr: Vec<_> = checks
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "ok": c.ok,
                    "detail": c.detail,
                    "fix": c.fix,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json!({ "checks": arr }))?);
    } else {
        for c in &checks {
            let icon = if c.ok { "✓" } else { "✗" };
            println!("{}  {:<28} {}", icon, c.name, c.detail);
        }
        if fix {
            let fixes: Vec<_> = checks
                .iter()
                .filter(|c| !c.ok)
                .filter_map(|c| c.fix.as_ref())
                .collect();
            if !fixes.is_empty() {
                println!("\n--- Suggested fixes ---");
                for f in fixes {
                    println!("{f}");
                }
            }
        }
        let all_ok = checks.iter().all(|c| c.ok);
        if all_ok {
            println!("\nAll checks passed.");
        } else {
            println!(
                "\nSome checks failed. To fill in keys: {}\n\
                 (use a local GUI Terminal and open the relevant chats while waiting; SIP does not need to be disabled)",
                config::RECOMMENDED_KEY_EXTRACT
            );
        }
    }
    Ok(())
}

fn run_checks() -> Vec<Check> {
    let mut out = Vec::new();

    // WeChat process
    let wechat_pid = find_wechat_pid();
    out.push(Check {
        name: "WeChat process".into(),
        ok: wechat_pid.is_some(),
        detail: wechat_pid
            .map(|p| format!("PID {p}"))
            .unwrap_or_else(|| "not running".into()),
        fix: Some("Log in to WeChat and keep it running".into()),
    });

    // SIP — 非致命；状态仅供参考
    #[cfg(target_os = "macos")]
    {
        let sip = Command::new("csrutil").arg("status").output().ok();
        let text = sip
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        let detail = if text.is_empty() {
            "unknown (key extraction does not require disabling SIP; use a local Terminal + sudo)".into()
        } else {
            format!(
                "{} — key extraction depends on task_for_pid/TCC, not on disabling SIP",
                text.trim()
            )
        };
        out.push(Check {
            name: "SIP".into(),
            ok: true,
            detail,
            fix: None,
        });
    }

    // codesign
    #[cfg(target_os = "macos")]
    {
        let sig = Command::new("codesign")
            .args(["-dvv", "/Applications/WeChat.app"])
            .output()
            .ok();
        let err = sig
            .as_ref()
            .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
            .unwrap_or_default();
        let kind = if err.contains("adhoc") || err.contains("Signature=adhoc") {
            "ad-hoc"
        } else if err.contains("runtime") || err.contains("0x10000") {
            "Hardened Runtime"
        } else if err.is_empty() {
            "not installed / unreadable"
        } else {
            "other"
        };
        out.push(Check {
            name: "WeChat signature".into(),
            ok: Path::new("/Applications/WeChat.app").exists(),
            detail: kind.into(),
            fix: Some("Website builds may be ad-hoc signed; for official Developer ID builds run the memory scan with sudo".into()),
        });
    }

    // lldb
    #[cfg(target_os = "macos")]
    {
        let has_lldb = Command::new("which")
            .arg("lldb")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        out.push(Check {
            name: "lldb".into(),
            ok: has_lldb,
            detail: if has_lldb {
                "available".into()
            } else {
                "not found".into()
            },
            fix: Some("xcode-select --install".into()),
        });
    }

    // config
    let cfg = config::load_config().ok();
    out.push(Check {
        name: "config.json".into(),
        ok: cfg.is_some(),
        detail: cfg
            .as_ref()
            .map(|c| c.db_dir.display().to_string())
            .unwrap_or_else(|| "not found, run wx init first".into()),
        fix: Some("wx init".into()),
    });

    // keys + missing shards
    if let Some(ref c) = cfg {
        let keys_ok = c.keys_file.exists();
        let (n_keys, known) = if keys_ok {
            load_known_entries(&c.keys_file)
        } else {
            (0, Vec::new())
        };
        out.push(Check {
            name: "Database keys".into(),
            ok: n_keys > 0,
            detail: format!("{n_keys} keys"),
            fix: Some(config::RECOMMENDED_KEY_EXTRACT.into()),
        });

        let missing = scanner::list_missing_encrypted_dbs(&c.db_dir, &known);
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

        if critical.is_empty() {
            out.push(Check {
                name: "Critical shard keys".into(),
                ok: n_keys > 0,
                detail: if n_keys > 0 {
                    "chat / session / contact complete".into()
                } else {
                    "no keys".into()
                },
                fix: None,
            });
        } else {
            let preview = format_missing_preview(&critical, 6);
            let total_mb: f64 = critical.iter().map(|m| m.size as f64).sum::<f64>()
                / (1024.0 * 1024.0);
            out.push(Check {
                name: "Critical shard keys".into(),
                ok: false,
                detail: format!(
                    "{} missing (about {:.0}MB): {}",
                    critical.len(),
                    total_mb,
                    preview
                ),
                fix: Some(format!(
                    "{}\n\
                     While waiting, open the matching chats in WeChat (to trigger cold shard loading):\n\
                     {}",
                    config::RECOMMENDED_KEY_EXTRACT,
                    critical
                        .iter()
                        .take(8)
                        .map(|m| format!("  · {} ({})", m.rel, scanner::format_db_size(m.size)))
                        .collect::<Vec<_>>()
                        .join("\n")
                )),
            });
        }

        if !optional.is_empty() {
            let preview = format_missing_preview(&optional, 4);
            out.push(Check {
                name: "Auxiliary DB keys".into(),
                ok: true, // 不阻断日常查询
                detail: format!(
                    "{} optional missing (e.g. migrate/*): {}",
                    optional.len(),
                    preview
                ),
                fix: Some(format!(
                    "Usually safe to ignore; if needed run {}",
                    config::RECOMMENDED_KEY_EXTRACT
                )),
            });
        }

        // SQLCipher online probe
        if let Some(session_key) = read_key_for(&c.keys_file, "session/session.db") {
            let session_path = c.db_dir.join("session/session.db");
            let online =
                crate::crypto::sqlcipher::open_encrypted_readonly(&session_path, &session_key);
            out.push(Check {
                name: "SQLCipher live open".into(),
                ok: online.is_ok(),
                detail: if online.is_ok() {
                    "session.db OK".into()
                } else {
                    format!("{:#}", online.err().unwrap())
                },
                fix: Some(format!(
                    "Make sure the keys match the WeChat version; {}",
                    config::RECOMMENDED_KEY_EXTRACT
                )),
            });
        }

        // FTS key
        let fts = read_key_for(&c.keys_file, "message/message_fts.db");
        out.push(Check {
            name: "message_fts key".into(),
            ok: fts.is_some(),
            detail: if fts.is_some() {
                "configured (search can use FTS)".into()
            } else {
                "missing (search falls back to a full scan)".into()
            },
            fix: Some(config::RECOMMENDED_KEY_EXTRACT.into()),
        });
    }

    // daemon sock
    let sock = config::sock_path();
    out.push(Check {
        name: "daemon socket".into(),
        ok: sock.exists(),
        detail: if sock.exists() {
            sock.display().to_string()
        } else {
            "not running (starts automatically on first query)".into()
        },
        fix: Some("wx sessions or wx daemon start".into()),
    });

    out
}

fn load_known_entries(keys_path: &Path) -> (usize, Vec<KeyEntry>) {
    let content = std::fs::read_to_string(keys_path).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap_or(json!({}));
    let mut known = Vec::new();
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
            if enc.len() == 64 {
                known.push(KeyEntry {
                    db_name: k.replace('\\', "/"),
                    enc_key: enc,
                    salt: String::new(),
                });
            }
        }
    }
    (known.len(), known)
}

fn format_missing_preview(items: &[scanner::MissingDb], max: usize) -> String {
    let parts: Vec<String> = items
        .iter()
        .take(max)
        .map(|m| format!("{} ({})", m.rel, scanner::format_db_size(m.size)))
        .collect();
    if items.len() > max {
        format!("{} …+{}", parts.join(", "), items.len() - max)
    } else {
        parts.join(", ")
    }
}

fn find_wechat_pid() -> Option<u32> {
    let out = Command::new("pgrep").args(["-x", "WeChat"]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

fn read_key_for(keys_path: &Path, rel: &str) -> Option<String> {
    let content = std::fs::read_to_string(keys_path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    let entry = v.get(rel)?;
    if let Some(s) = entry.as_str() {
        return Some(s.to_string());
    }
    entry
        .get("enc_key")
        .and_then(|e| e.as_str())
        .map(|s| s.to_string())
}
