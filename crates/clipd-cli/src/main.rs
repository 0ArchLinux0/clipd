//! clipd — lightweight cross-platform clipboard sync daemon.

use anyhow::Result;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    match std::env::args().nth(1).as_deref() {
        Some("serve") => {
            let id = clipd_core::identity::DeviceIdentity::load_or_create(&data_dir()?)?;
            println!("device fingerprint: {}", id.pairing_fingerprint());
            // TODO(phase-1): mDNS advertise + clipboard watcher + QUIC sync loop
            clipd_core::transport::serve(47_407).await?;
        }
        Some("scan") => {
            println!("scanning LAN for clipd peers…");
            for (ip, peer) in clipd_core::discovery::scan(Duration::from_secs(3))? {
                println!(
                    "{:15} {} ({}) port:{}",
                    ip, peer.device_name, peer.device_id, peer.quic_port
                );
            }
        }
        Some("copy") => {
            let text = std::env::args().nth(2).unwrap_or_else(|| {
                use std::io::Read;
                let mut buf = String::new();
                let _ = std::io::stdin().read_to_string(&mut buf);
                buf
            });
            clipd_clipboard::write_text(&text)?;
            println!("copied {} bytes", text.len());
        }
        Some("paste") => {
            if let Some(t) = clipd_clipboard::read_text()? {
                print!("{t}");
            }
        }
        Some("whoami") => {
            let id = clipd_core::identity::DeviceIdentity::load_or_create(&data_dir()?)?;
            println!("{}", id.pairing_fingerprint());
        }
        other => {
            eprintln!(
                "clipd v{}\n\nUSAGE:\n  clipd serve    run the daemon\n  clipd scan     find peers on this network\n  clipd copy [text|-]\n  clipd paste",
                clipd_core::VERSION
            );
            if other.is_some() {
                anyhow::bail!("unknown command: {other:?}")
            }
        }
    }
    Ok(())
}

fn data_dir() -> Result<std::path::PathBuf> {
    if cfg!(target_os = "macos") {
        let home = std::env::var("HOME")?;
        Ok(std::path::PathBuf::from(format!("{home}/Library/Application Support/clipd")))
    } else {
        Ok(std::path::PathBuf::from(".clipd"))
    }
}
