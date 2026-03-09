use netbird_embed::{Client, ClientOptions};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let setup_key =
        std::env::var("NB_SETUP_KEY").expect("NB_SETUP_KEY environment variable required");
    let management_url =
        std::env::var("NB_MANAGEMENT_URL").unwrap_or_else(|_| "https://api.netbird.io".to_string());
    let device_name =
        std::env::var("NB_DEVICE_NAME").unwrap_or_else(|_| "rust-example".to_string());

    println!("Creating NetBird client...");
    let client = Client::new(ClientOptions {
        setup_key: Some(setup_key),
        management_url: Some(management_url),
        device_name: Some(device_name),
        ..Default::default()
    })?;

    println!("Starting client...");
    client.start()?;

    println!("Connected. Polling status...");
    for _ in 0..30 {
        match client.status() {
            Ok(status) => {
                println!(
                    "IP: {}, mgmt: {}, signal: {}, peers: {}",
                    status.ip,
                    status.management_state,
                    status.signal_state,
                    status.peers.len()
                );
                if status.management_state == "connected" {
                    break;
                }
            }
            Err(e) => eprintln!("Status error: {e}"),
        }
        thread::sleep(Duration::from_secs(1));
    }

    println!("\nPeers:");
    match client.peers() {
        Ok(peers) => {
            for peer in &peers {
                println!(
                    "  {} ({}) — {} {}",
                    peer.fqdn,
                    peer.ip,
                    peer.conn_status,
                    if peer.relayed {
                        "[relayed]"
                    } else {
                        "[direct]"
                    }
                );
            }
        }
        Err(e) => eprintln!("Peers error: {e}"),
    }

    println!("\nPress Ctrl+C to stop...");
    loop {
        thread::sleep(Duration::from_secs(5));
    }
}
