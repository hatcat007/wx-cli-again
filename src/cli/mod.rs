pub mod attachments;
pub mod biz_articles;
pub mod contacts;
pub mod daemon_cmd;
pub mod doctor;
pub mod export;
pub mod extract;
pub mod favorites;
pub mod history;
pub(crate) mod init;
pub mod key_cmd;
pub mod media;
pub mod members;
pub mod new_messages;
pub mod output;
pub mod search;
pub mod sessions;
pub mod sns_feed;
pub mod sns_notifications;
pub mod sns_search;
pub mod stats;
pub mod timeline;
pub mod transport;
pub mod unread;
pub mod watch;

use self::output::OutputOpts;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Clap `value_parser` for `--type`: must accept every slug/`type_id` and numeric codes
/// that `history::parse_msg_type` knows — closed string lists reject agent round-trips.
fn clap_parse_msg_type(s: &str) -> std::result::Result<String, String> {
    history::parse_msg_type_required(s)
        .map(|_| s.to_string())
        .map_err(|e| e.to_string())
}

const MSG_TYPE_HELP: &str = "Message type filter [text|image|voice|video|card|sticker|location|link|file|appmsg|call|system|revoke|numeric code]";

/// wx — WeChat local data CLI
#[derive(Parser)]
#[command(name = "wx", version = env!("CARGO_PKG_VERSION"), about = "wx — WeChat local data CLI")]
pub struct Cli {
    /// Return heavier freshness/source metadata (e.g. per-shard latest, cache modes)
    #[arg(long, global = true)]
    with_meta: bool,
    /// Expose real shard paths in meta (for debugging)
    #[arg(long, global = true, hide = true)]
    debug_source: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize: detect data directory and scan for encryption keys
    Init {
        /// Force rescan (merged with existing valid keys; partial failure does not clear them)
        #[arg(long)]
        force: bool,
        /// macOS: LLDB hook wait in seconds (0 = disabled). When the memory scan misses cold shards,
        /// open WeChat chats during the wait to capture per-DB AES keys.
        #[arg(long)]
        hook_seconds: Option<u64>,
    },
    /// List recent sessions
    Sessions {
        /// Number of sessions
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// View chat history
    History {
        /// Chat name (fuzzy match)
        chat: String,
        /// Number of messages
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Pagination offset (deep offsets are slow; prefer the --after cursor)
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Cursor: only return messages older than this time (Unix seconds or date; usually the oldest timestamp of the previous page)
        #[arg(long)]
        after: Option<String>,
        /// Cursor: only return messages newer than this time
        #[arg(long)]
        before: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Search messages
    Search {
        /// Search keyword
        keyword: String,
        /// Restrict to chat (can be repeated)
        #[arg(long = "in", value_name = "CHAT")]
        chats: Vec<String>,
        /// Number of results
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// View contacts
    Contacts {
        /// Filter by name
        #[arg(short = 'q', long)]
        query: Option<String>,
        /// Number to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Export chat history to a file
    Export {
        /// Chat name
        chat: String,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Maximum messages to export
        #[arg(short = 'n', long, default_value = "500")]
        limit: usize,
        /// Output format [markdown|txt|json|yaml]
        #[arg(short = 'f', long, default_value = "markdown", value_parser = ["markdown", "txt", "json", "yaml"])]
        format: String,
        /// Output file (default stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
    },
    /// Show sessions with unread messages
    Unread {
        /// Number to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Filter by session type, comma-separated. Example: --filter private,group shows only unread from real people
        #[arg(long, value_name = "TYPES", value_delimiter = ',',
              value_parser = ["all", "private", "group", "official", "folded"])]
        filter: Vec<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// View group members
    Members {
        /// Group name (fuzzy match)
        chat: String,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Get new messages since the last check
    NewMessages {
        /// Maximum number to show
        #[arg(short = 'n', long, default_value = "200")]
        limit: usize,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Chat statistics
    Stats {
        /// Chat name (fuzzy match)
        chat: String,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// View WeChat favorites
    Favorites {
        /// Number to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Type filter [text|image|article|card|video]
        #[arg(long = "type", value_name = "TYPE",
              value_parser = ["text","image","article","card","video"])]
        fav_type: Option<String>,
        /// Search content by keyword
        #[arg(short = 'q', long)]
        query: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Moments notifications: likes/comments on my posts + replies under posts I commented on
    SnsNotifications {
        /// Number to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Include read notifications (default: unread only)
        #[arg(long)]
        include_read: bool,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Moments timeline: filter locally cached Moments by time/author
    SnsFeed {
        /// Number to show
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Only show this author (nickname / remark / WeChat ID, fuzzy match)
        #[arg(long)]
        user: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Query official account articles (local cache)
    BizArticles {
        /// Number to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Restrict to official account (fuzzy name match)
        #[arg(long)]
        account: Option<String>,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Only accounts with unread items, latest 1 article each
        #[arg(long)]
        unread: bool,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Moments full-text search: match keyword in post text
    SnsSearch {
        /// Keyword
        keyword: String,
        /// Number of results
        #[arg(short = 'n', long, default_value = "20")]
        limit: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Restrict to author (nickname / remark / WeChat ID)
        #[arg(long)]
        user: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// List image attachments in a chat, returning opaque attachment_ids
    Attachments {
        /// Chat name (contact display name / wxid / @chatroom username)
        chat: String,
        /// Type (currently only image)
        #[arg(long = "kind", value_name = "KIND",
              value_parser = ["image", "img"])]
        kinds: Vec<String>,
        /// Number to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Start date YYYY-MM-DD
        #[arg(long)]
        since: Option<String>,
        /// End date YYYY-MM-DD
        #[arg(long)]
        until: Option<String>,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Decrypt the resource for one attachment_id and write it to a file path
    Extract {
        /// Opaque ID from `wx attachments` (base64url string)
        attachment_id: String,
        /// Output file path (absolute or relative to cwd; keep an extension like .jpg)
        #[arg(short = 'o', long)]
        output: String,
        /// Overwrite if the target exists
        #[arg(long)]
        overwrite: bool,
        /// Output JSON (default YAML)
        #[arg(long)]
        json: bool,
    },
    /// Manage wx-daemon
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCommands,
    },
    /// Environment / key / shard health check
    Doctor {
        /// Output JSON
        #[arg(long)]
        json: bool,
        /// Print suggested fix commands
        #[arg(long)]
        fix: bool,
    },
    /// Key management
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Cross-chat timeline (merge messages from multiple chats by time)
    Timeline {
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        #[arg(long, default_value = "0")]
        offset: usize,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// Cursor: only return messages older than this time
        #[arg(long)]
        after: Option<String>,
        #[arg(long = "type", value_name = "TYPE", help = MSG_TYPE_HELP, value_parser = clap_parse_msg_type)]
        msg_type: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Watch for new messages in real time (polls session.db)
    Watch {
        /// Poll interval in milliseconds
        #[arg(long, default_value = "1500")]
        interval: u64,
        /// Maximum messages fetched per poll
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Media tools (voice, etc.)
    Media {
        #[command(subcommand)]
        action: MediaAction,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Extract keys by scanning process memory / LLDB hook (sudo recommended)
    Extract {
        #[arg(long)]
        hook_seconds: Option<u64>,
    },
    /// List keys in all_keys.json
    List {
        #[arg(long)]
        json: bool,
        /// Print full enc_key (default preview only, to avoid leaking by accidental paste)
        #[arg(long)]
        show_secrets: bool,
    },
    /// Manually set the key for one DB
    Set {
        /// Relative path, e.g. message/message_1.db
        db: String,
        /// 64-character hex
        enc_key: String,
    },
}

#[derive(Subcommand)]
enum MediaAction {
    /// Export raw voice silk data from message/media_0.db by svr_id
    Voice {
        /// Message server id / svr_id
        svr_id: i64,
        /// Optional chat username (speeds up lookup)
        #[arg(long)]
        chat: Option<String>,
        /// Output path (.silk)
        #[arg(short = 'o', long)]
        output: String,
    },
}

#[derive(Subcommand)]
pub enum DaemonCommands {
    /// Show daemon status
    Status,
    /// Stop daemon
    Stop,
    /// Show daemon logs
    Logs {
        /// Follow output (tail -f)
        #[arg(short = 'f', long)]
        follow: bool,
        /// Show last N lines
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },
}

pub fn run() {
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let base_with_meta = cli.with_meta;
    let base_debug_source = cli.debug_source;
    match cli.command {
        Commands::Init {
            force,
            hook_seconds,
        } => init::cmd_init(force, hook_seconds),
        Commands::Sessions { limit, json } => sessions::cmd_sessions(
            limit,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::History {
            chat,
            limit,
            offset,
            since,
            until,
            after,
            before,
            msg_type,
            json,
        } => history::cmd_history(
            chat,
            limit,
            offset,
            since,
            until,
            after,
            before,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Search {
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            json,
        } => search::cmd_search(
            keyword,
            chats,
            limit,
            since,
            until,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Contacts { query, limit, json } => contacts::cmd_contacts(query, limit, json),
        Commands::Export {
            chat,
            since,
            until,
            limit,
            format,
            output,
        } => {
            let export_json = format == "json";
            export::cmd_export(
                chat,
                since,
                until,
                limit,
                format,
                output,
                OutputOpts {
                    json: export_json,
                    with_meta: base_with_meta,
                    debug_source: base_debug_source,
                },
            )
        }
        Commands::Unread {
            limit,
            filter,
            json,
        } => unread::cmd_unread(
            limit,
            filter,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Members { chat, json } => members::cmd_members(chat, json),
        Commands::NewMessages { limit, json } => new_messages::cmd_new_messages(
            limit,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Stats {
            chat,
            since,
            until,
            json,
        } => stats::cmd_stats(
            chat,
            since,
            until,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Favorites {
            limit,
            fav_type,
            query,
            json,
        } => favorites::cmd_favorites(limit, fav_type, query, json),
        Commands::SnsNotifications {
            limit,
            since,
            until,
            include_read,
            json,
        } => sns_notifications::cmd_sns_notifications(limit, since, until, include_read, json),
        Commands::SnsFeed {
            limit,
            since,
            until,
            user,
            json,
        } => sns_feed::cmd_sns_feed(limit, since, until, user, json),
        Commands::SnsSearch {
            keyword,
            limit,
            since,
            until,
            user,
            json,
        } => sns_search::cmd_sns_search(keyword, limit, since, until, user, json),
        Commands::BizArticles {
            limit,
            account,
            since,
            until,
            unread,
            json,
        } => biz_articles::cmd_biz_articles(limit, account, since, until, unread, json),
        Commands::Attachments {
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            json,
        } => attachments::cmd_attachments(
            chat,
            kinds,
            limit,
            offset,
            since,
            until,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Extract {
            attachment_id,
            output,
            overwrite,
            json,
        } => extract::cmd_extract(attachment_id, output, overwrite, json),
        Commands::Daemon { cmd } => daemon_cmd::cmd_daemon(cmd),
        Commands::Doctor { json, fix } => doctor::cmd_doctor(json, fix),
        Commands::Key { action } => match action {
            KeyAction::Extract { hook_seconds } => key_cmd::cmd_key_extract(hook_seconds),
            KeyAction::List { json, show_secrets } => key_cmd::cmd_key_list(json, show_secrets),
            KeyAction::Set { db, enc_key } => key_cmd::cmd_key_set(&db, &enc_key),
        },
        Commands::Timeline {
            limit,
            offset,
            since,
            until,
            after,
            msg_type,
            json,
        } => timeline::cmd_timeline(
            limit,
            offset,
            since,
            until,
            after,
            msg_type,
            OutputOpts {
                json,
                with_meta: base_with_meta,
                debug_source: base_debug_source,
            },
        ),
        Commands::Watch {
            interval,
            limit,
            json,
        } => watch::cmd_watch(
            interval,
            limit,
            OutputOpts {
                json,
                with_meta: false,
                debug_source: false,
            },
        ),
        Commands::Media { action } => match action {
            MediaAction::Voice {
                svr_id,
                chat,
                output,
            } => media::cmd_voice_export(svr_id, chat, output),
        },
    }
}

#[cfg(test)]
mod clap_msg_type_wiring_tests {
    use super::Cli;
    use clap::Parser;

    /// Real CLI parse path (not just parse_msg_type helper): clap value_parser must accept
    /// agent type_id round-trips and numeric codes.
    #[test]
    fn history_accepts_appmsg_card_revoke_and_digit_type() {
        for ty in ["appmsg", "card", "revoke", "49", "link", "text"] {
            let cli = Cli::try_parse_from(["wx", "history", "someone", "--type", ty])
                .unwrap_or_else(|e| panic!("--type {ty} must parse: {e}"));
            match cli.command {
                super::Commands::History { msg_type, .. } => {
                    assert_eq!(msg_type.as_deref(), Some(ty));
                }
                _ => panic!("expected History for --type {ty}"),
            }
        }
    }

    #[test]
    fn search_and_timeline_accept_appmsg() {
        let s = Cli::try_parse_from(["wx", "search", "kw", "--type", "appmsg"])
            .expect("search --type appmsg");
        match s.command {
            super::Commands::Search { msg_type, .. } => {
                assert_eq!(msg_type.as_deref(), Some("appmsg"));
            }
            _ => panic!("expected Search"),
        }
        let t = Cli::try_parse_from(["wx", "timeline", "--type", "57"]).expect("timeline --type 57");
        match t.command {
            super::Commands::Timeline { msg_type, .. } => {
                assert_eq!(msg_type.as_deref(), Some("57"));
            }
            _ => panic!("expected Timeline"),
        }
    }

    #[test]
    fn clap_rejects_unknown_type_before_dispatch() {
        let err = match Cli::try_parse_from(["wx", "history", "x", "--type", "nope"]) {
            Ok(_) => panic!("unknown --type must fail at clap parse"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("Unknown message type") || msg.contains("nope"),
            "unexpected error: {msg}"
        );
    }
}
