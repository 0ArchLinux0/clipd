//! LAN discovery via mDNS.
//!
//! Each clipd instance advertises `_clipd._udp.local` with its device ID and
//! QUIC port. Discovery alone never grants trust — peers discovered here are
//! "visible" until they present a pinned public key from a completed pairing.

use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::time::Duration;

pub const SERVICE_TYPE: &str = "_clipd._udp.local.";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerAdvertisement {
    /// Hex-encoded ed25519 public key fingerprint (short form)
    pub device_id: String,
    pub device_name: String,
    pub quic_port: u16,
}

/// Advertise this device on the local network.
pub fn advertise(port: u16, adv: &PeerAdvertisement) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new()?;
    let props = [
        ("device_id", adv.device_id.as_str()),
        ("device_name", adv.device_name.as_str()),
        ("port", &adv.quic_port.to_string()),
    ];
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &adv.device_id,
        &format!("{host}.local.", host = adv.device_id),
        "",
        port,
        &props[..],
    )?;
    daemon.register(info)?;
    Ok(daemon)
}

/// Scan for peer advertisements on the LAN.
///
/// Returns the first N peers found within `timeout`. Never blocks longer
/// than `timeout` overall.
pub fn scan(timeout: Duration) -> Result<Vec<(String /* ip */, PeerAdvertisement)>> {
    let daemon = ServiceDaemon::new()?;
    let receiver = daemon.browse(SERVICE_TYPE)?;

    let mut found = Vec::new();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        match receiver.recv_timeout(deadline - std::time::Instant::now()) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let props = info.get_properties();
                if let (Some(id), Some(name)) = (
                    props.get_property_val_str("device_id"),
                    props.get_property_val_str("device_name"),
                ) {
                    let port: u16 = props
                        .get_property_val_str("port")
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(0);
                    found.push((
                        info.get_addresses()
                            .iter()
                            .next()
                            .map(|ip| ip.to_string())
                            .unwrap_or_default(),
                        PeerAdvertisement {
                            device_id: id.to_string(),
                            device_name: name.to_string(),
                            quic_port: port,
                        },
                    ));
                }
            }
            Ok(_) => {}
            // Phase-0: any channel/timeout error just ends the scan window.
            Err(e) => {
                tracing::debug!(error = %e, "mdns scan ended");
                break;
            }
        }
    }
    let _ = daemon.stop_browse(SERVICE_TYPE);
    Ok(found)
}
