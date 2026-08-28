//! clipd — lightweight cross-platform clipboard sync daemon.
//!
//! Command map (see docs/ARCHITECTURE.md for pipelines):
//!   serve   = mDNS advertise + QUIC accept loop + signed receive policy
//!   send    = connect → handshake → signed ClipboardText → Ack
//!   pair    = TOFU handshake + SAS verify-code display, pin peer key

use anyhow::{bail, Context, Result};
use clipd_core::identity::DeviceIdentity;
use clipd_core::peers::{PeerEntry, PeerStore};
use clipd_core::protocol::Frame;
use clipd_core::session::{self, FrameHandler, SessionMeta};
use clipd_core::sync::{process_incoming, ClipboardSink, LamportClock, LoopGuard};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("serve") {
        cmd_serve().await;
        unreachable!("serve loop never exits");
    }
    match args.get(1).map(|s| s.as_str()) {
        Some("scan") => cmd_scan()?,
        Some("send") => cmd_send(args.get(2).map(String::as_str)).await?,
        Some("pair") => cmd_pair(args.get(2).context("usage: clipd pair <ip:port>")?).await?,
        Some("unpair") => cmd_unpair(args.get(2).context("usage: clipd unpair <id>")?)?,
        Some("peers") => cmd_peers()?,
        Some("copy") => cmd_copy(args.get(2))?,
        Some("paste") => cmd_paste()?,
        Some("whoami") => cmd_whoami()?,
        Some("smoke") => cmd_smoke().await?,
        other => print_usage(other),
    }
    Ok(())
}

fn print_usage(unknown: Option<&str>) {
    eprintln!(
        "clipd v{}\n\nUSAGE:\n\
         clipd serve            run the daemon (LAN sync)\n\
         clipd scan             discover peers on this network\n\
         clipd send [ip:port]   push local clipboard to a peer\n\
         clipd pair <ip:port>   pair with a device (verify SAS code!)\n\
         clipd unpair <id>      forget a device\n\
         clipd peers            list known devices\n\
         clipd copy [text|-]    copy text or stdin to clipboard\n\
         clipd paste            print clipboard\n\
         clipd whoami\n\
         clipd smoke            in-process local loop: send → OS clipboard update → assert",
        clipd_core::VERSION
    );
    if unknown.is_some() {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// shared state helpers

fn data_dir() -> Result<std::path::PathBuf> {
    if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").context("HOME unset; cannot determine data dir")?;
        Ok(std::path::PathBuf::from(format!(
            "{home}/Library/Application Support/clipd"
        )))
    } else if cfg!(target_os = "windows") {
        let appdata =
            std::env::var("APPDATA").context("APPDATA unset; cannot determine data dir")?;
        Ok(std::path::PathBuf::from(format!("{appdata}\\clipd")))
    } else {
        Ok(std::path::PathBuf::from(".clipd"))
    }
}

fn device_name() -> String {
    std::env::var("CLIPD_DEVICE_NAME")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

/// The real OS clipboard target. Dedup/echo logic lives upstream (`LoopGuard`
/// inside `process_incoming`), so this stays dumb and honest.
struct OsClipboard;

impl ClipboardSink for OsClipboard {
    fn apply_text(&mut self, text: &str) -> Result<bool> {
        clipd_clipboard::write_text(text)?;
        tracing::info!(bytes = text.len(), "clipboard updated from peer");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// commands

fn cmd_whoami() -> Result<()> {
    let dir = data_dir()?;
    let id = DeviceIdentity::load_or_create(&dir)?;
    let peers = PeerStore::load(dir.join("peers.json"))?;
    println!("device_id:      {}", id.device_id());
    println!("fingerprint:    {}", id.pairing_fingerprint());
    println!("paired devices: {}", peers.len());
    Ok(())
}

fn cmd_copy(arg: Option<&String>) -> Result<()> {
    let text = match arg.map(|s| s.as_str()) {
        Some("-") | None => {
            use std::io::Read;
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            buf
        }
        Some(t) => t.to_string(),
    };
    clipd_clipboard::write_text(&text)?;
    println!("copied {} bytes", text.len());
    Ok(())
}

fn cmd_paste() -> Result<()> {
    if let Some(t) = clipd_clipboard::read_text()? {
        print!("{t}");
    }
    Ok(())
}

fn cmd_scan() -> Result<()> {
    println!("scanning LAN for clipd peers…");
    let found = clipd_core::discovery::scan(Duration::from_secs(3))?;
    if found.is_empty() {
        println!("(none found)");
    }
    for (ip, peer) in found {
        println!(
            "{:15} {} ({}) port:{}",
            ip, peer.device_name, peer.device_id, peer.quic_port
        );
    }
    Ok(())
}

fn cmd_peers() -> Result<()> {
    let peers = PeerStore::load(data_dir()?.join("peers.json"))?;
    if peers.is_empty() {
        println!("no paired devices yet");
        return Ok(());
    }
    for (id, e) in peers.iter() {
        println!("{id}  {}  last_addr:{}", e.device_name, e.last_addr);
    }
    Ok(())
}

fn cmd_unpair(device_id: &str) -> Result<()> {
    let mut peers = PeerStore::load(data_dir()?.join("peers.json"))?;
    if peers.remove(device_id) {
        peers.save()?;
        println!("unpaired {device_id}");
    } else {
        bail!("unknown device {device_id}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// pair

async fn cmd_pair(addr: &str) -> Result<()> {
    let dir = data_dir()?;
    let identity = DeviceIdentity::load_or_create(&dir)?;
    let conn = clipd_core::transport::connect(addr).await?;

    // Trust-On-First-Use: server reveals identity over encrypted channel; we
    // record it and surface a SAS code the user compares on both screens.
    let meta = session::client_handshake(&conn, &identity, None).await?;
    let sas = sas_code(&identity, &meta)?;

    println!("peer:     {} ({})", meta.device_name, meta.device_id);
    println!("VERIFY CODE: {}", sas);
    println!("Compare with the same code shown on the other device.");
    println!("Codes must match. Mismatch = attacker on this network.");

    let mut peers = PeerStore::load(dir.join("peers.json"))?;
    peers.insert(
        meta.device_id.clone(),
        PeerEntry {
            device_name: meta.device_name.clone(),
            public_key: meta.public_key.clone(),
            last_addr: addr.to_string(),
            added_at_secs: now_secs(),
        },
    );
    peers.save()?;
    println!("saved trusted device {}", meta.device_id);

    conn.close(0u32.into(), b"paired");
    Ok(())
}

fn sas_code(identity: &DeviceIdentity, meta: &SessionMeta) -> Result<String> {
    let mine: [u8; 32] = hex::decode(identity.public_key_hex())?
        .as_slice()
        .try_into()?;
    let theirs: [u8; 32] = hex::decode(meta.public_key.clone())?
        .as_slice()
        .try_into()?;
    Ok(clipd_core::sas::pairing_code(&mine, &theirs))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// send

async fn cmd_send(addr: Option<&str>) -> Result<()> {
    let dir = data_dir()?;
    let identity = DeviceIdentity::load_or_create(&dir)?;
    let peers = PeerStore::load(dir.join("peers.json"))?;

    let target = match addr {
        Some(a) => a.to_string(),
        None => first_discovered_peer()
            .await
            .context("no clipd peers found on this network")?,
    };

    let text = clipd_clipboard::read_text()?.context("local clipboard is empty")?;
    let conn = clipd_core::transport::connect(&target).await?;
    let mut clock = LamportClock::new();
    let lamport =
        session::send_clipboard_text(&conn, &identity, &mut clock, &text, Some(&peers)).await?;
    tracing::info!(to = %target, sent_lamport = lamport, bytes = text.len(), "sent");
    println!("sent to {} ({})", target, lamport);
    conn.close(0u32.into(), b"done");
    Ok(())
}

async fn first_discovered_peer() -> Option<String> {
    let found = clipd_core::discovery::scan(Duration::from_secs(3)).ok()?;
    found
        .first()
        .and_then(|(ip, p)| (!ip.is_empty()).then(|| format!("{ip}:{}", p.quic_port)))
}

// ---------------------------------------------------------------------------
// serve (daemon)

async fn cmd_serve() -> std::convert::Infallible {
    let dir = data_dir().expect("data dir");
    let identity = Arc::new(DeviceIdentity::load_or_create(&dir).expect("load identity"));
    let peers = Arc::new(tokio::sync::Mutex::new(
        PeerStore::load(dir.join("peers.json")).expect("load peers"),
    ));

    println!("clipd daemon starting");
    println!("  device_id:   {}", identity.device_id());
    println!("  fingerprint: {}", identity.pairing_fingerprint());
    println!("  fpr command: clipd whoami");

    // --- QUIC endpoint ------------------------------------------------------
    // Honor CLIPD_QUIC_PORT for tests / multi-instance setups; default 47407.
    let quic_port: u16 = std::env::var("CLIPD_QUIC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(47_407);
    let ep = clipd_core::transport::bind(quic_port)
        .await
        .expect("binding QUIC");
    let port = ep.local_addr().expect("local addr").port();

    // --- mDNS advertisement -------------------------------------------------
    // mdns-sd's ServiceDaemon runs its own threads; pin it on a dedicated OS
    // thread so its lifetime never depends on the async executor.
    {
        let adv = clipd_core::discovery::PeerAdvertisement {
            device_id: identity.device_id(),
            device_name: device_name(),
            quic_port: port,
        };
        let service =
            clipd_core::discovery::advertise(port, &adv).expect("mdns advertisement failed");
        std::thread::Builder::new()
            .name("clipd-mdns".into())
            .spawn(move || {
                let _keep_alive = service; // handle held until process exit
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            })
            .expect("spawning mdns thread");
    }

    // --- receive-side sync state -------------------------------------------
    // std Mutexes: held only for microseconds inside the sync handler.
    let guard = Arc::new(std::sync::Mutex::new(LoopGuard::new()));
    let clock = Arc::new(std::sync::Mutex::new(LamportClock::new()));

    // --- accept loop ---------------------------------------------------------
    loop {
        let incoming = match ep.accept().await {
            Some(i) => i,
            None => break,
        };
        let identity = identity.clone();
        let peers = peers.clone();
        let guard = guard.clone();
        let clock = clock.clone();

        let handler: FrameHandler<'static> = Arc::new(tokio::sync::Mutex::new(
            move |meta: SessionMeta, frame: Frame| -> Result<Option<Frame>> {
                match frame {
                    Frame::ClipboardText {
                        text,
                        origin,
                        lamport,
                        signature,
                    } => {
                        // `serve_connection` has enforced pairing rules on
                        // `meta`; here we verify content auth + integrity,
                        // suppress echoes, then apply to the OS clipboard.
                        let mut sink = OsClipboard;
                        let mut g = guard.lock().expect("loop guard poisoned");
                        let mut c = clock.lock().expect("lamport poisoned");
                        let (_, remote_lamport) = process_incoming(
                            &meta.device_id,
                            &origin,
                            &signature,
                            &text,
                            lamport,
                            &meta.public_key,
                            &mut g,
                            &mut c,
                            &mut sink,
                        )?;
                        Ok(Some(Frame::Ack {
                            lamport: remote_lamport,
                        }))
                    }
                    _ => Ok(None),
                }
            },
        ));

        tokio::spawn(async move {
            // Wait for the QUIC handshake to complete, then serve.
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) =
                        session::serve_connection(conn, identity, peers, false, handler).await
                    {
                        tracing::warn!(error = %e, "connection ended");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "quic handshake failed"),
            }
        });
    }
    unreachable!("endpoint loop never ends")
}

// ---------------------------------------------------------------------------
// smoke: in-process end-to-end loop
//
// Spins up a server (same machinery as `serve` but with a self-signed trust
// store so we don't need prior pairing) on an ephemeral port, then has a
// second identity connect and send a known text. Polls the OS clipboard
// until that text appears, asserts, and exits 0/1.
//
// Why not a unit test: `OsClipboard` writes the real OS clipboard, so
// arboard has to be wired against the actual platform. The `clipd smoke`
// command is the user-runnable equivalent of that test.
async fn cmd_smoke() -> Result<()> {
    use clipd_core::session::serve_connection;
    use clipd_core::sync::{process_incoming, LamportClock, LoopGuard};

    // 1) Two ephemeral identities (don't touch real ~/Library/Application Support/clipd).
    let tmp = std::env::temp_dir().join(format!("clipd-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let server_id = Arc::new(DeviceIdentity::load_or_create(&tmp.join("server"))?);
    let client_id = Arc::new(DeviceIdentity::load_or_create(&tmp.join("client"))?);
    let peers = Arc::new(tokio::sync::Mutex::new(PeerStore::load(
        tmp.join("server").join("peers.json"),
    )?));

    // 2) Marker so the poll is unambiguous even if clipboard already has the text.
    let payload = format!("clipd-smoke-ok-{}", std::process::id());
    println!("[smoke] will send: {payload}");

    // 3) Bind a server-side QUIC endpoint on an ephemeral port.
    let ep = clipd_core::transport::bind(0).await?;
    let port = ep.local_addr()?.port();
    let addr = format!("127.0.0.1:{port}");

    // 4) Hand-rolled serve task identical to cmd_serve's per-connection logic.
    let guard = Arc::new(std::sync::Mutex::new(LoopGuard::new()));
    let clock = Arc::new(std::sync::Mutex::new(LamportClock::new()));
    let payload_for_handler = payload.clone();
    let applied = Arc::new(std::sync::Mutex::new(false));
    let applied_flag = applied.clone();
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = ep.accept().await {
            let sid = server_id.clone();
            let peers = peers.clone();
            let g = guard.clone();
            let c = clock.clone();
            let p = payload_for_handler;
            let applied = applied_flag.clone();
            let handler: FrameHandler<'static> = Arc::new(tokio::sync::Mutex::new(
                move |meta: SessionMeta, frame: Frame| -> Result<Option<Frame>> {
                    if let Frame::ClipboardText {
                        text,
                        origin,
                        lamport,
                        signature,
                    } = frame
                    {
                        let mut sink = OsClipboard;
                        let mut g = g.lock().expect("guard");
                        let mut c = c.lock().expect("clock");
                        let (_, rl) = process_incoming(
                            &meta.device_id,
                            &origin,
                            &signature,
                            &text,
                            lamport,
                            &meta.public_key,
                            &mut g,
                            &mut c,
                            &mut sink,
                        )?;
                        *applied.lock().expect("flag") = true;
                        let _ = p; // payload captured for clarity; not needed in handler
                        Ok(Some(Frame::Ack { lamport: rl }))
                    } else {
                        Ok(None)
                    }
                },
            ));
            if let Ok(conn) = incoming.await {
                let _ = serve_connection(conn, sid, peers, false, handler).await;
            }
        }
    });

    // 5) Pre-flight: make sure the OS clipboard is NOT already holding the
    //    payload (otherwise poll would succeed trivially).
    if let Some(existing) = clipd_clipboard::read_text()? {
        if existing == payload {
            anyhow::bail!(
                "OS clipboard already contains smoke marker; run again with a fresh shell"
            );
        }
    }
    // Save & restore so we don't clobber the user's clipboard.
    let saved = clipd_clipboard::read_text()?;

    // 6) Connect from the client identity, send the payload.
    let conn = clipd_core::transport::connect(&addr).await?;
    let mut cclock = LamportClock::new();
    let _lamport =
        session::send_clipboard_text(&conn, &client_id, &mut cclock, &payload, None).await?;
    conn.close(0u32.into(), b"smoke-done");

    // 7) Poll the OS clipboard up to ~2s for the payload to appear.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut got = false;
    while std::time::Instant::now() < deadline {
        if let Some(t) = clipd_clipboard::read_text()? {
            if t == payload {
                got = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 8) Restore the user's original clipboard content (best-effort).
    if let Some(prev) = saved {
        let _ = clipd_clipboard::write_text(&prev);
    }

    server_task.abort();

    if !got {
        anyhow::bail!("[smoke] FAIL: OS clipboard did not contain {payload:?} after 2s");
    }
    if !*applied.lock().expect("flag") {
        anyhow::bail!("[smoke] FAIL: handler reported applied=false");
    }
    println!("[smoke] PASS: payload reached OS clipboard via QUIC");
    Ok(())
}
