use std::net::SocketAddr;
use std::path::PathBuf;

use crate::exchange::{ExchangeOptions, ExchangePeer};

pub enum Command {
    GenKey {
        private_keys_dir: PathBuf,
    },
    PubKey {
        private_keys_dir: PathBuf,
        public_keys_dir: PathBuf,
    },
    Exchange(ExchangeOptions),
}

enum CommandType {
    GenKey,
    PubKey,
    Exchange,
}

#[derive(Default)]
pub struct Cli {
    pub verbose: bool,
    pub command: Option<Command>,
}

fn fatal<T>(note: &str, command: Option<CommandType>) -> Result<T, String> {
    match command {
        Some(command) => match command {
            CommandType::GenKey => Err(format!("{}\nUsage: rp genkey PRIVATE_KEYS_DIR", note)),
            CommandType::PubKey => Err(format!("{}\nUsage: rp pubkey PRIVATE_KEYS_DIR PUBLIC_KEYS_DIR", note)),
            CommandType::Exchange => Err(format!("{}\nUsage: rp exchange PRIVATE_KEYS_DIR [dev <device>] [listen <ip>:<port>] [peer PUBLIC_KEYS_DIR [endpoint <ip>:<port>] [persistent-keepalive <interval>] [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...]]...", note)),
        },
        None => Err(format!("{}\nUsage: rp [explain] [verbose] genkey|pubkey|exchange [ARGS]...", note)),
    }
}

impl ExchangePeer {
    pub fn parse(args: &mut &mut impl Iterator<Item = String>) -> Result<Self, String> {
        let mut peer = ExchangePeer::default();

        if let Some(public_keys_dir) = args.next() {
            peer.public_keys_dir = PathBuf::from(public_keys_dir);
        } else {
            return fatal(
                "Required positional argument: PUBLIC_KEYS_DIR",
                Some(CommandType::Exchange),
            );
        }

        while let Some(x) = args.next() {
            let x = x.as_str();

            match x {
                "endpoint" => {
                    if let Some(addr) = args.next() {
                        if let Ok(addr) = addr.parse::<SocketAddr>() {
                            peer.endpoint = Some(addr);
                        } else {
                            return fatal(
                                "invalid parameter for listen option",
                                Some(CommandType::Exchange),
                            );
                        }
                    } else {
                        return fatal(
                            "listen option requires parameter",
                            Some(CommandType::Exchange),
                        );
                    }
                }
                "persistent-keepalive" => {
                    if let Some(ka) = args.next() {
                        if let Ok(ka) = ka.parse::<u32>() {
                            peer.persistent_keepalive = Some(ka);
                        } else {
                            return fatal(
                                "invalid parameter for persistent-keepalive option",
                                Some(CommandType::Exchange),
                            );
                        }
                    } else {
                        return fatal(
                            "persistent-keepalive option requires parameter",
                            Some(CommandType::Exchange),
                        );
                    }
                }
                "allowed-ips" => {
                    if let Some(ips) = args.next() {
                        peer.allowed_ips = Some(ips);
                    } else {
                        return fatal(
                            "allowed-ips option requires parameter",
                            Some(CommandType::Exchange),
                        );
                    }
                }
                _ => {
                    return fatal(
                        &format!("Unknown option {}", x),
                        Some(CommandType::Exchange),
                    )
                }
            }
        }

        Ok(peer)
    }
}

impl ExchangeOptions {
    pub fn parse(mut args: &mut impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = ExchangeOptions::default();

        if let Some(private_keys_dir) = args.next() {
            options.private_keys_dir = PathBuf::from(private_keys_dir);
        } else {
            return fatal(
                "Required positional argument: PRIVATE_KEYS_DIR",
                Some(CommandType::Exchange),
            );
        }

        while let Some(x) = args.next() {
            let x = x.as_str();

            match x {
                "dev" => {
                    if let Some(device) = args.next() {
                        options.dev = Some(device);
                    } else {
                        return fatal("dev option requires parameter", Some(CommandType::Exchange));
                    }
                }
                "listen" => {
                    if let Some(addr) = args.next() {
                        if let Ok(addr) = addr.parse::<SocketAddr>() {
                            options.listen = Some(addr);
                        } else {
                            return fatal(
                                "invalid parameter for listen option",
                                Some(CommandType::Exchange),
                            );
                        }
                    } else {
                        return fatal(
                            "listen option requires parameter",
                            Some(CommandType::Exchange),
                        );
                    }
                }
                "peer" => {
                    let peer = ExchangePeer::parse(&mut args)?;
                    options.peers.push(peer);
                }
                _ => {
                    return fatal(
                        &format!("Unknown option {}", x),
                        Some(CommandType::Exchange),
                    )
                }
            }
        }

        Ok(options)
    }
}

impl Cli {
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut cli = Cli::default();

        let _ = args.next(); // skip executable name

        while let Some(x) = args.next() {
            let x = x.as_str();

            match x {
                "verbose" => {
                    cli.verbose = true;
                }
                "genkey" => {
                    if cli.command.is_some() {
                        return fatal("Too many commands supplied", None);
                    }

                    if let Some(private_keys_dir) = args.next() {
                        let private_keys_dir = PathBuf::from(private_keys_dir);

                        cli.command = Some(Command::GenKey { private_keys_dir });
                    } else {
                        return fatal(
                            "Required positional argument: PRIVATE_KEYS_DIR",
                            Some(CommandType::GenKey),
                        );
                    }
                }
                "pubkey" => {
                    if cli.command.is_some() {
                        return fatal("Too many commands supplied", None);
                    }

                    if let Some(private_keys_dir) = args.next() {
                        let private_keys_dir = PathBuf::from(private_keys_dir);

                        if let Some(public_keys_dir) = args.next() {
                            let public_keys_dir = PathBuf::from(public_keys_dir);

                            cli.command = Some(Command::PubKey {
                                private_keys_dir,
                                public_keys_dir,
                            });
                        } else {
                            return fatal(
                                "Required positional argument: PUBLIC_KEYS_DIR",
                                Some(CommandType::PubKey),
                            );
                        }
                    } else {
                        return fatal(
                            "Required positional argument: PRIVATE_KEYS_DIR",
                            Some(CommandType::PubKey),
                        );
                    }
                }
                "exchange" => {
                    if cli.command.is_some() {
                        return fatal("Too many commands supplied", None);
                    }

                    let options = ExchangeOptions::parse(&mut args)?;
                    cli.command = Some(Command::Exchange(options));
                }
                _ => return fatal(&format!("Unknown command {}", x), None),
            };
        }

        if cli.command.is_none() {
            return fatal("No command supplied", None);
        }

        Ok(cli)
    }
}
