use anyhow::{bail, Context, Result};
use base64::Engine;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::history::{parse_time, parse_time_end};
use super::output::{emit_warnings, print_value, resolve};
use super::transport;
use crate::ipc::Request;

const PAGE: usize = 200;

pub struct OcrArgs {
    pub chat: String,
    pub out: String,
    pub limit: Option<usize>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub endpoint: String,
    pub model: String,
    pub prompt: String,
    pub json: bool,
}

/// `wx ocr` — decrypt every image in a chat and OCR it with a local LM Studio model.
///
/// Per image: `<out>/<time>_<local_id>.<ext>` plus `<same>.txt` with the OCR text.
/// Images whose .txt already exists are skipped, so re-runs resume.
pub fn cmd_ocr(a: OcrArgs) -> Result<()> {
    require_loopback(&a.endpoint)?;
    let since_ts = a.since.as_deref().map(parse_time).transpose()?;
    let until_ts = a.until.as_deref().map(parse_time_end).transpose()?;

    let out_dir = PathBuf::from(&a.out);
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("Failed to create {}", out_dir.display()))?;
    let out_dir = out_dir.canonicalize()?;

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(600))
        .build();
    let url = format!("{}/chat/completions", a.endpoint.trim_end_matches('/'));

    let mut results = Vec::new();
    let (mut done, mut skipped, mut failed) = (0usize, 0usize, 0usize);
    let mut offset = 0;
    'pages: loop {
        let resp = transport::send(Request::Attachments {
            chat: a.chat.clone(),
            kinds: None,
            limit: PAGE,
            offset,
            since: since_ts,
            until: until_ts,
            with_meta: false,
            debug_source: false,
        })?;
        emit_warnings(&resp.data);
        let items = resp.data["attachments"].as_array().cloned().unwrap_or_default();
        for item in &items {
            if a.limit.is_some_and(|n| done + skipped + failed >= n) {
                break 'pages;
            }
            let id = item["attachment_id"].as_str().unwrap_or_default();
            let stem = format!(
                "{}_{}",
                item["time"].as_str().unwrap_or("").replace([' ', ':'], "-"),
                item["local_id"]
            );
            let txt_path = out_dir.join(format!("{stem}.txt"));
            let mut row = json!({
                "time": item["time"],
                "sender": item.get("sender").cloned().unwrap_or(Value::Null),
                "text_file": txt_path.display().to_string(),
            });
            if txt_path.exists() {
                skipped += 1;
                row["status"] = "skipped".into();
                results.push(row);
                continue;
            }
            match ocr_one(&agent, &url, &a, id, &out_dir, &stem, &txt_path) {
                Ok((image, chars)) => {
                    done += 1;
                    eprintln!("[ocr] {} ({} chars)", image.display(), chars);
                    row["status"] = "ok".into();
                    row["image"] = image.display().to_string().into();
                    row["chars"] = chars.into();
                }
                Err(e) => {
                    failed += 1;
                    eprintln!("[ocr] {stem} failed: {e:#}");
                    row["status"] = "failed".into();
                    row["error"] = format!("{e:#}").into();
                }
            }
            results.push(row);
        }
        if items.len() < PAGE {
            break;
        }
        offset += PAGE;
    }

    print_value(
        &json!({
            "chat": a.chat,
            "out_dir": out_dir.display().to_string(),
            "ocr_done": done,
            "skipped": skipped,
            "failed": failed,
            "items": results,
        }),
        &resolve(a.json),
    )
}

fn ocr_one(
    agent: &ureq::Agent,
    url: &str,
    a: &OcrArgs,
    id: &str,
    out_dir: &Path,
    stem: &str,
    txt_path: &Path,
) -> Result<(PathBuf, usize)> {
    // Decrypt to a temp name, then rename with the real extension the decoder detected.
    let tmp = out_dir.join(format!("{stem}.img"));
    let resp = transport::send(Request::Extract {
        attachment_id: id.to_string(),
        output: tmp.display().to_string(),
        overwrite: true,
    })?;
    let fmt = resp.data["format"].as_str().unwrap_or("jpg").to_string();
    let image = out_dir.join(format!("{stem}.{fmt}"));
    std::fs::rename(&tmp, &image)?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(std::fs::read(&image)?);
    let mime = if fmt == "jpg" { "jpeg".to_string() } else { fmt };
    let body = json!({
        "model": a.model,
        "temperature": 0,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": a.prompt},
                {"type": "image_url", "image_url": {"url": format!("data:image/{mime};base64,{b64}")}},
            ],
        }],
    });
    let reply: Value = match agent.post(url).set("Content-Type", "application/json").send_string(&body.to_string()) {
        Ok(r) => serde_json::from_str(&r.into_string()?)?,
        Err(ureq::Error::Status(code, r)) => {
            bail!("LM Studio HTTP {code}: {}", r.into_string().unwrap_or_default())
        }
        Err(e) => bail!("Cannot reach LM Studio at {url} (is the server running?): {e}"),
    };
    let text = reply["choices"][0]["message"]["content"]
        .as_str()
        .context("LM Studio reply has no choices[0].message.content")?
        .trim()
        .to_string();
    std::fs::write(txt_path, &text)?;
    Ok((image, text.chars().count()))
}

/// Images never leave the machine: only plain-HTTP loopback endpoints are accepted.
fn require_loopback(endpoint: &str) -> Result<()> {
    let rest = endpoint
        .strip_prefix("http://")
        .context("--endpoint must start with http:// (local LM Studio server)")?;
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        Ok(())
    } else {
        bail!("--endpoint host must be localhost / 127.0.0.1 / [::1], got '{host}'")
    }
}

#[cfg(test)]
mod tests {
    use super::require_loopback;

    #[test]
    fn only_loopback_endpoints_allowed() {
        for ok in ["http://localhost:1234/v1", "http://127.0.0.1:1234/v1", "http://[::1]:1234/v1", "http://localhost/v1"] {
            assert!(require_loopback(ok).is_ok(), "{ok}");
        }
        for bad in [
            "https://localhost:1234/v1",
            "http://example.com/v1",
            "http://localhost.evil.com/v1",
            "http://192.168.1.5:1234/v1",
            "http://user@evil.com:1234/v1",
            "localhost:1234",
        ] {
            assert!(require_loopback(bad).is_err(), "{bad}");
        }
    }
}
