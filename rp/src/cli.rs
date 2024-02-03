use std::path::PathBuf;
use std::{iter::Peekable, net::SocketAddr};

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
    pub fn parse(args: &mut &mut Peekable<impl Iterator<Item = String>>) -> Result<Self, String> {
        let mut peer = ExchangePeer::default();

        if let Some(public_keys_dir) = args.next() {
            peer.public_keys_dir = PathBuf::from(public_keys_dir);
        } else {
            return fatal(
                "Required positional argument: PUBLIC_KEYS_DIR",
                Some(CommandType::Exchange),
            );
        }

        while let Some(x) = args.peek() {
            let x = x.as_str();

            // break if next peer is being defined
            if x == "peer" {
                break;
            }

            let x = args.next().unwrap();
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
    pub fn parse(mut args: &mut Peekable<impl Iterator<Item = String>>) -> Result<Self, String> {
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
    pub fn parse(mut args: Peekable<impl Iterator<Item = String>>) -> Result<Self, String> {
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

#[cfg(test)]
mod tests {
    use crate::cli::{Cli, Command};

    #[inline]
    fn parse(arr: &[&str]) -> Result<Cli, String> {
        Cli::parse(arr.into_iter().map(|x| x.to_string()).peekable())
    }

    #[inline]
    fn parse_err(arr: &[&str]) -> bool {
        parse(arr).is_err()
    }

    #[test]
    fn bare_errors() {
        assert!(parse_err(&["rp"]));
        assert!(parse_err(&["rp", "verbose"]));
        assert!(parse_err(&["rp", "thiscommanddoesntexist"]));
        assert!(parse_err(&[
            "rp",
            "thiscommanddoesntexist",
            "genkey",
            "./fakedir/"
        ]));
    }

    #[test]
    fn genkey_errors() {
        assert!(parse_err(&["rp", "genkey"]));
    }

    #[test]
    fn genkey_works() {
        let cli = parse(&["rp", "genkey", "./fakedir"]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();

        assert_eq!(cli.verbose, false);
        assert!(matches!(cli.command, Some(Command::GenKey { .. })));

        match cli.command {
            Some(Command::GenKey { private_keys_dir }) => {
                assert_eq!(private_keys_dir.to_str().unwrap(), "./fakedir");
            }
            _ => unreachable!(),
        };
    }

    #[test]
    fn pubkey_errors() {
        assert!(parse_err(&["rp", "pubkey"]));
        assert!(parse_err(&["rp", "pubkey", "./fakedir"]));
    }

    #[test]
    fn pubkey_works() {
        let cli = parse(&["rp", "pubkey", "./fakedir", "./fakedir2"]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();

        assert_eq!(cli.verbose, false);
        assert!(matches!(cli.command, Some(Command::PubKey { .. })));

        match cli.command {
            Some(Command::PubKey {
                private_keys_dir,
                public_keys_dir,
            }) => {
                assert_eq!(private_keys_dir.to_str().unwrap(), "./fakedir");
                assert_eq!(public_keys_dir.to_str().unwrap(), "./fakedir2");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn exchange_errors() {
        assert!(parse_err(&["rp", "exchange"]));
        assert!(parse_err(&[
            "rp",
            "exchange",
            "./fakedir",
            "notarealoption"
        ]));
        assert!(parse_err(&["rp", "exchange", "./fakedir", "listen"]));
        assert!(parse_err(&[
            "rp",
            "exchange",
            "./fakedir",
            "listen",
            "notarealip"
        ]));
    }

    #[test]
    fn exchange_works() {
        let cli = parse(&["rp", "exchange", "./fakedir"]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();

        assert_eq!(cli.verbose, false);
        assert!(matches!(cli.command, Some(Command::Exchange(_))));

        match cli.command {
            Some(Command::Exchange(options)) => {
                assert_eq!(options.private_keys_dir.to_str().unwrap(), "./fakedir");
                assert!(options.dev.is_none());
                assert!(options.listen.is_none());
                assert_eq!(options.peers.len(), 0);
            }
            _ => unreachable!(),
        }

        let cli = parse(&[
            "rp",
            "exchange",
            "./fakedir",
            "dev",
            "devname",
            "listen",
            "127.0.0.1:1234",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();

        assert_eq!(cli.verbose, false);
        assert!(matches!(cli.command, Some(Command::Exchange(_))));

        match cli.command {
            Some(Command::Exchange(options)) => {
                assert_eq!(options.private_keys_dir.to_str().unwrap(), "./fakedir");
                assert_eq!(options.dev, Some("devname".to_string()));
                assert_eq!(options.listen, Some("127.0.0.1:1234".parse().unwrap()));
                assert_eq!(options.peers.len(), 0);
            }
            _ => unreachable!(),
        }

        let cli = parse(&[
            "rp",
            "exchange",
            "./fakedir",
            "dev",
            "devname",
            "listen",
            "127.0.0.1:1234",
            "peer",
            "./fakedir2",
            "endpoint",
            "127.0.0.1:2345",
            "persistent-keepalive",
            "15",
            "allowed-ips",
            "123.234.11.0/24,1.1.1.0/24",
            "peer",
            "./fakedir3",
            "endpoint",
            "127.0.0.1:5432",
            "persistent-keepalive",
            "30",
        ]);

        assert!(cli.is_ok());
        let cli = cli.unwrap();

        assert_eq!(cli.verbose, false);
        assert!(matches!(cli.command, Some(Command::Exchange(_))));

        match cli.command {
            Some(Command::Exchange(options)) => {
                assert_eq!(options.private_keys_dir.to_str().unwrap(), "./fakedir");
                assert_eq!(options.dev, Some("devname".to_string()));
                assert_eq!(options.listen, Some("127.0.0.1:1234".parse().unwrap()));
                assert_eq!(options.peers.len(), 2);

                let peer = &options.peers[0];
                assert_eq!(peer.public_keys_dir.to_str().unwrap(), "./fakedir2");
                assert_eq!(peer.endpoint, Some("127.0.0.1:2345".parse().unwrap()));
                assert_eq!(peer.persistent_keepalive, Some(15));
                assert_eq!(
                    peer.allowed_ips,
                    Some("123.234.11.0/24,1.1.1.0/24".to_string())
                );

                let peer = &options.peers[1];
                assert_eq!(peer.public_keys_dir.to_str().unwrap(), "./fakedir3");
                assert_eq!(peer.endpoint, Some("127.0.0.1:5432".parse().unwrap()));
                assert_eq!(peer.persistent_keepalive, Some(30));
                assert!(peer.allowed_ips.is_none());
            }
            _ => unreachable!(),
        }
    }
}
