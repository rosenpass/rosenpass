use std::fs;
use std::path::PathBuf;
use std::process::exit;

use clap::Parser;
use rosenpass::{
    app_server::AppServer,
    cmdline::Cmdline,
    config::Config,
    net::network_manager::{DefaultNetworkManager, NetworkManager},
    peer::{Peer, PeerName},
    transport::Transport,
};
use rosenpass_util::{
    file::load_secret_bytes_from_file,
    fs::create_dir_all,
    io::IoErrorContext,
    logging,
    path::PathExt,
    timing::DurationExt,
};

#[cfg(feature = "experiment_memfd_secret")]
use rosenpass_secret_memory::policy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging();

    #[cfg(feature = "experiment_memfd_secret")]
    policy::secret_policy_try_use_memfd_secrets();
    #[cfg(not(feature = "experiment_memfd_secret"))]
    policy::secret_policy_use_only_malloc_secrets();

    let cmdline = match Cmdline::parse() {
        Ok(cmdline) => cmdline,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };

    if cmdline.verbose {
        logging::set_max_level(log::LevelFilter::Debug);
    }

    let config = match Config::load(&cmdline.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Failed to load config: {}", err);
            exit(1);
        }
    };

    // Initialize network manager
    let network_manager = DefaultNetworkManager::new();

    if !network_manager.is_available() {
        eprintln!("Warning: No supported network manager available (systemd-networkd not found)");
    }

    let mut app_server = AppServer::new(config.clone(), cmdline.verbose);

    // Setup network configuration if needed
    if let Some(network_config) = &config.network {
        if let Err(e) = setup_network_config(&network_manager, network_config).await {
            eprintln!("Failed to setup network configuration: {}", e);
            exit(1);
        }
    }

    app_server.run().await
}

async fn setup_network_config<N: NetworkManager>(
    network_manager: &N,
    network_config: &rosenpass::config::NetworkConfig,
) -> anyhow::Result<()> {
    use rosenpass::config::NetworkBackend;

    match &network_config.backend {
        NetworkBackend::SystemdNetworkd(config) => {
            // Generate systemd-networkd configuration
            let networkd_config = generate_systemd_networkd_config(config)?;

            // Write configuration to file
            let config_path = PathBuf::from("/etc/systemd/network/99-rosenpass.network");
            network_manager
                .apply_config(&networkd_config, &config_path)
                .context("Failed to apply systemd-networkd configuration")?;

            // Reload network configuration
            network_manager
                .reload()
                .context("Failed to reload network configuration")?;
        }
    }

    Ok(())
}

fn generate_systemd_networkd_config(config: &rosenpass::config::SystemdNetworkdConfig) -> anyhow::Result<String> {
    let mut output = String::new();

    // Network section
    output.push_str("[Match]\n");
    if let Some(name) = &config.interface_name {
        output.push_str(&format!("Name={}\n", name));
    }
    output.push_str("\n");

    output.push_str("[Network]\n");
    if let Some(address) = &config.address {
        output.push_str(&format!("Address={}\n", address));
    }
    if let Some(gateway) = &config.gateway {
        output.push_str(&format!("Gateway={}\n", gateway));
    }
    if let Some(dns) = &config.dns {
        output.push_str(&format!("DNS={}\n", dns));
    }
    if let Some(domain) = &config.domain {
        output.push_str(&format!("Domains={}\n", domain));
    }

    Ok(output)
}