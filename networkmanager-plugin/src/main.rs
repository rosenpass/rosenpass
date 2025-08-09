//! Main entry point for the Rosenpass NetworkManager plugin

use anyhow::Result;
use clap::Parser;
use log::{info, error};
use std::path::PathBuf;
use std::sync::Arc;
use zbus::ConnectionBuilder;

use rosenpass_networkmanager_plugin::{
    RosenpassConnectionManager,
    RosenpassDBusService,
    dbus_service::DBusSignalEmitter,
    DBUS_SERVICE_NAME,
    DBUS_OBJECT_PATH,
};

/// Command line arguments for the NetworkManager plugin
#[derive(Parser, Debug)]
#[command(
    name = "rosenpass-nm-plugin",
    about = "NetworkManager plugin for Rosenpass post-quantum key exchange",
    version
)]
struct Args {
    /// Configuration directory path
    #[arg(
        short,
        long,
        default_value = "/etc/NetworkManager/rosenpass",
        help = "Directory containing Rosenpass connection configurations"
    )]
    config_dir: PathBuf,
    
    /// Log level
    #[arg(
        short,
        long,
        default_value = "info",
        help = "Set log level (error, warn, info, debug, trace)"
    )]
    log_level: String,
    
    /// Run as system service
    #[arg(
        long,
        help = "Run as system D-Bus service (requires root or appropriate permissions)"
    )]
    system: bool,
    
    /// Print configuration template and exit
    #[arg(
        long,
        help = "Print a configuration template and exit"
    )]
    print_template: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Handle template printing
    if args.print_template {
        print_configuration_template();
        return Ok(());
    }
    
    // Initialize logging
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&args.log_level)
    ).init();
    
    info!("Starting Rosenpass NetworkManager plugin v{}", 
          rosenpass_networkmanager_plugin::VERSION);
    
    // Create config directory if it doesn't exist
    if !args.config_dir.exists() {
        std::fs::create_dir_all(&args.config_dir)?;
        info!("Created configuration directory: {:?}", args.config_dir);
    }
    
    // Create the connection manager
    let manager = RosenpassConnectionManager::new(args.config_dir.clone());
    
    // Set up D-Bus connection
    let connection = if args.system {
        info!("Connecting to system D-Bus");
        ConnectionBuilder::system()?
            .name(DBUS_SERVICE_NAME)?
            .build()
            .await?
    } else {
        info!("Connecting to session D-Bus");
        ConnectionBuilder::session()?
            .name(DBUS_SERVICE_NAME)?
            .build()
            .await?
    };
    
    info!("Connected to D-Bus as service: {}", DBUS_SERVICE_NAME);
    
    // Create the D-Bus service
    let manager_arc = Arc::new(manager);
    let service = RosenpassDBusService::new(manager_arc.clone());
    
    // Set up the object server
    let object_server = connection.object_server();
    object_server
        .at(DBUS_OBJECT_PATH, service)
        .await?;
    
    info!("D-Bus service registered at path: {}", DBUS_OBJECT_PATH);
    
    // Create signal emitter and set it on the manager  
    let signal_emitter = Arc::new(DBusSignalEmitter::new(connection.clone()));
    
    // Actually, let's restructure this properly
    let manager = {
        let mut mgr = RosenpassConnectionManager::new(args.config_dir.clone());
        mgr.set_signal_emitter(signal_emitter);
        mgr
    };
    
    // Load initial configurations
    if let Err(err) = manager.load_configurations().await {
        error!("Failed to load initial configurations: {}", err);
        return Err(err.into());
    }
    
    // Create the D-Bus service with the properly configured manager
    let service = RosenpassDBusService::new(Arc::new(manager));
    
    // Replace the service in the object server
    object_server
        .at(DBUS_OBJECT_PATH, service)
        .await?;
    
    info!("Rosenpass NetworkManager plugin started successfully");
    info!("Configuration directory: {:?}", args.config_dir);
    info!("D-Bus service: {} at {}", DBUS_SERVICE_NAME, DBUS_OBJECT_PATH);
    
    // Set up signal handlers
    setup_signal_handlers().await?;
    
    // Keep the service running
    std::future::pending::<()>().await;
    
    Ok(())
}

/// Set up signal handlers for graceful shutdown
async fn setup_signal_handlers() -> Result<()> {
    use tokio::signal;
    
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    
    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down gracefully");
                std::process::exit(0);
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down gracefully");
                std::process::exit(0);
            }
        }
    });
    
    Ok(())
}

/// Print a configuration template
fn print_configuration_template() {
    let template = r#"# Rosenpass NetworkManager Plugin Configuration Template
# Save this as /etc/NetworkManager/rosenpass/{connection-uuid}.toml

# NetworkManager connection UUID (replace with actual UUID)
connection_uuid = "12345678-1234-5678-9abc-123456789abc"

# Path to our public key file
public_key = "/etc/rosenpass/public.key"

# Path to our secret key file
secret_key = "/etc/rosenpass/secret.key"

# Port to listen on for incoming connections
listen_port = 9999

# Optional: specific addresses to listen on (defaults to all interfaces)
# listen_addresses = ["192.168.1.100", "::1"]

# WireGuard interface name
wireguard_interface = "wg0"

# Optional: path to output shared key for WireGuard
# key_output = "/tmp/rosenpass-key"

# Optional: enable verbose logging
verbose = false

# Peer configurations
[[peers]]
# Peer's public key file
public_key = "/etc/rosenpass/peer.pub"

# Peer's endpoint (IP:port) - optional for responder-only mode
endpoint = "peer.example.com:9999"

# WireGuard peer public key (base64 encoded)
wireguard_peer = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# Optional: pre-shared key file for this peer
# preshared_key = "/etc/rosenpass/peer.psk"

# Add more peers as needed:
# [[peers]]
# public_key = "/etc/rosenpass/peer2.pub"
# endpoint = "peer2.example.com:9999"
# wireguard_peer = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
"#;
    
    println!("{}", template);
}