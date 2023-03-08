use anyhow::{bail, ensure, Context, Result};
use log::{error, info};
use rosenpass::{
    attempt,
    coloring::{Public, Secret},
    multimatch,
    pqkem::{SKEM, KEM},
    protocol::{SPk, SSk, MsgBuf, PeerPtr, Server as CryptoServer, SymKey, Timing},
    sodium::sodium_init,
    util::{b64_reader, b64_writer, fmt_b64},
};
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    path::Path,
    process::{exit, Command, Stdio},
    time::Duration,
};

/// Open a file writable
pub fn fopen_w<P: AsRef<Path>>(path: P) -> Result<File> {
    Ok(OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}
/// Open a file readable
pub fn fopen_r<P: AsRef<Path>>(path: P) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)?)
}

pub trait ReadExactToEnd {
    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<()>;
}

impl<R: Read> ReadExactToEnd for R {
    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut dummy = [0u8; 8];
        self.read_exact(buf)?;
        ensure!(self.read(&mut dummy)? == 0, "File too long!");
        Ok(())
    }
}

pub trait LoadValue {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;
}

pub trait LoadValueB64 {
    fn load_b64<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;
}

trait StoreValue {
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<()>;
}

trait StoreSecret {
    unsafe fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()>;
}

impl<T: StoreValue> StoreSecret for T {
    unsafe fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.store(path)
    }
}

impl<const N: usize> LoadValue for Secret<N> {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut v = Self::random();
        let p = path.as_ref();
        fopen_r(p)?
            .read_exact_to_end(v.secret_mut())
            .with_context(|| format!("Could not load file {p:?}"))?;
        Ok(v)
    }
}

impl<const N: usize> LoadValueB64 for Secret<N> {
    fn load_b64<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut v = Self::random();
        let p = path.as_ref();
        // This might leave some fragments of the secret on the stack;
        // in practice this is likely not a problem because the stack likely
        // will be overwritten by something else soon but this is not exactly
        // guaranteed. It would be possible to remedy this, but since the secret
        // data will linger in the linux page cache anyways with the current
        // implementation, going to great length to erase the secret here is
        // not worth it right now.
        b64_reader(&mut fopen_r(p)?)
            .read_exact(v.secret_mut())
            .with_context(|| format!("Could not load base64 file {p:?}"))?;
        Ok(v)
    }
}

impl<const N: usize> StoreSecret for Secret<N> {
    unsafe fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        std::fs::write(path, self.secret())?;
        Ok(())
    }
}

impl<const N: usize> LoadValue for Public<N> {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut v = Self::random();
        fopen_r(path)?.read_exact_to_end(&mut *v)?;
        Ok(v)
    }
}

impl<const N: usize> StoreValue for Public<N> {
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        std::fs::write(path, **self)?;
        Ok(())
    }
}

macro_rules! bail_usage {
    ($args:expr, $($pt:expr),*) => {{
        error!($($pt),*);
        cmd_help()?;
        exit(1);
    }}
}

macro_rules! ensure_usage {
    ($args:expr, $ck:expr, $($pt:expr),*) => {{
        if !$ck {
            bail_usage!($args, $($pt),*);
        }
    }}
}

macro_rules! mandatory_opt {
    ($args:expr, $val:expr, $name:expr) => {{
        ensure_usage!($args, $val.is_some(), "{0} option is mandatory", $name)
    }};
}

pub struct ArgsWalker {
    pub argv: Vec<String>,
    pub off: usize,
}

impl ArgsWalker {
    pub fn get(&self) -> Option<&str> {
        self.argv.get(self.off).map(|s| s as &str)
    }

    pub fn prev(&mut self) -> Option<&str> {
        assert!(self.off > 0);
        self.off -= 1;
        self.get()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<&str> {
        assert!(self.todo() > 0);
        self.off += 1;
        self.get()
    }

    pub fn opt(&mut self, dst: &mut Option<String>) -> Result<()> {
        let cmd = &self.argv[self.off - 1];
        ensure_usage!(&self, self.todo() > 0, "Option {} takes a value", cmd);
        ensure_usage!(&self, dst.is_none(), "Cannot set {} multiple times.", cmd);
        *dst = Some(String::from(self.next().unwrap()));
        Ok(())
    }

    fn todo(&self) -> usize {
        self.argv.len() - self.off
    }
}

#[derive(Default, Debug)]
pub struct WireguardOut {
    // impl KeyOutput
    dev: String,
    pk: String,
    extra_params: Vec<String>,
}

#[derive(Default, Debug)]
pub struct AppPeer {
    pub outfile: Option<String>,
    pub outwg: Option<WireguardOut>,
    pub tx_addr: Option<SocketAddr>,
}

#[derive(Debug)]
pub enum Verbosity {
    Quiet,
    Verbose,
}

/// Holds the state of the application, namely the external IO
#[derive(Debug)]
pub struct AppServer {
    pub crypt: CryptoServer,
    pub sock: UdpSocket,
    pub peers: Vec<AppPeer>,
    pub verbosity: Verbosity,
}

/// Index based pointer to a Peer
#[derive(Debug)]
pub struct AppPeerPtr(pub usize);

impl AppPeerPtr {
    /// Takes an index based handle and returns the actual peer
    pub fn lift(p: PeerPtr) -> Self {
        Self(p.0)
    }

    /// Returns an index based handle to one Peer
    pub fn lower(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    pub fn get_app<'a>(&self, srv: &'a AppServer) -> &'a AppPeer {
        &srv.peers[self.0]
    }

    pub fn get_app_mut<'a>(&self, srv: &'a mut AppServer) -> &'a mut AppPeer {
        &mut srv.peers[self.0]
    }
}

#[derive(Debug)]
pub enum AppPollResult {
    DeleteKey(AppPeerPtr),
    SendInitiation(AppPeerPtr),
    SendRetransmission(AppPeerPtr),
    ReceivedMessage(usize, SocketAddr),
}

#[derive(Debug)]
pub enum KeyOutputReason {
    Exchanged,
    Stale,
}

/// Catches errors, prints them through the logger, then exits
pub fn main() {
    env_logger::init();
    match rosenpass_main() {
        Ok(_) => {}
        Err(e) => {
            error!("{e}");
            exit(1);
        }
    }
}

/// Entry point to the whole program
pub fn rosenpass_main() -> Result<()> {
    sodium_init()?;

    let mut args = ArgsWalker {
        argv: std::env::args().collect(),
        off: 0, // skipping executable path
    };

    // Command parsing
    match args.next() {
        Some("help") | Some("-h") | Some("-help") | Some("--help") => cmd_help()?,
        Some("keygen") => cmd_keygen(args)?,
        Some("exchange") => cmd_exchange(args)?,
        Some(cmd) => bail_usage!(&args, "No such command {}", cmd),
        None => bail_usage!(&args, "Expected a command!"),
    };

    Ok(())
}

/// Print the usage information
pub fn cmd_help() -> Result<()> {
    eprint!(include_str!("usage.md"), env!("CARGO_BIN_NAME"));
    Ok(())
}

/// Generate a keypair
pub fn cmd_keygen(mut args: ArgsWalker) -> Result<()> {
    let mut sf: Option<String> = None;
    let mut pf: Option<String> = None;

    // Arg parsing
    loop {
        match args.next() {
            Some("private-key") => args.opt(&mut sf)?,
            Some("public-key") => args.opt(&mut pf)?,
            Some(opt) => bail_usage!(&args, "Unknown option `{}`", opt),
            None => break,
        };
    }

    mandatory_opt!(&args, sf, "private-key");
    mandatory_opt!(&args, pf, "private-key");

    // Cmd
    let (mut ssk, mut spk) = (SSk::random(), SPk::random());
    unsafe {
        SKEM::keygen(ssk.secret_mut(), spk.secret_mut())?;
        ssk.store_secret(sf.unwrap())?;
        spk.store_secret(pf.unwrap())?;
    }

    Ok(())
}

pub fn cmd_exchange(mut args: ArgsWalker) -> Result<()> {
    // Argument parsing
    let mut sf: Option<String> = None;
    let mut pf: Option<String> = None;
    let mut listen: Option<String> = None;
    let mut verbosity = Verbosity::Quiet;

    // Global parameters
    loop {
        match args.next() {
            Some("private-key") => args.opt(&mut sf)?,
            Some("public-key") => args.opt(&mut pf)?,
            Some("listen") => args.opt(&mut listen)?,
            Some("verbose") => {
                verbosity = Verbosity::Verbose;
            }
            Some("peer") => {
                args.prev();
                break;
            }
            Some(opt) => bail_usage!(&args, "Unknown option `{}`", opt),
            None => break,
        };
    }

    mandatory_opt!(&args, sf, "private-key");
    mandatory_opt!(&args, pf, "public-key");

    let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
        // sk, pk, addr
        SSk::load(&sf.unwrap())?,
        SPk::load(&pf.unwrap())?,
        listen.as_deref().unwrap_or("[0::0]:0"),
        verbosity,
    )?);

    // Peer parameters
    '_parseAllPeers: while args.todo() > 0 {
        let mut pf: Option<String> = None;
        let mut outfile: Option<String> = None;
        let mut outwg: Option<WireguardOut> = None;
        let mut endpoint: Option<String> = None;
        let mut pskf: Option<String> = None;

        args.next(); // skip "peer" starter itself

        'parseOnePeer: loop {
            match args.next() {
                // Done with this peer
                Some("peer") => {
                    args.prev();
                    break 'parseOnePeer;
                }
                None => break 'parseOnePeer,
                // Options
                Some("public-key") => args.opt(&mut pf)?,
                Some("endpoint") => args.opt(&mut endpoint)?,
                Some("preshared-key") => args.opt(&mut pskf)?,
                Some("outfile") => args.opt(&mut outfile)?,
                // Wireguard out
                Some("wireguard") => {
                    ensure_usage!(
                        &args,
                        outwg.is_none(),
                        "Cannot set wireguard output for the same peer multiple times."
                    );
                    ensure_usage!(&args, args.todo() >= 2, "Option wireguard takes to values");
                    let dev = String::from(args.next().unwrap());
                    let pk = String::from(args.next().unwrap());
                    let wg = outwg.insert(WireguardOut {
                        dev,
                        pk,
                        extra_params: Vec::new(),
                    });
                    '_parseWgOutExtra: loop {
                        match args.next() {
                            Some("peer") => {
                                args.prev();
                                break 'parseOnePeer;
                            }
                            None => break 'parseOnePeer,
                            Some(xtra) => wg.extra_params.push(xtra.to_string()),
                        };
                    }
                }
                // Invalid
                Some(opt) => bail_usage!(&args, "Unknown peer option `{}`", opt),
            };
        }

        mandatory_opt!(&args, pf, "private-key");
        ensure_usage!(
            &args,
            outfile.is_some() || outwg.is_some(),
            "Either of the outfile or wireguard option is mandatory"
        );

        let tx_addr = endpoint
            .map(|e| {
                e.to_socket_addrs()?
                    .next()
                    .context("Expected address in endpoint parameter")
            })
            .transpose()?;

        srv.add_peer(
            // psk, pk, outfile, outwg, tx_addr
            pskf.map(SymKey::load_b64).transpose()?,
            SPk::load(&pf.unwrap())?,
            outfile,
            outwg,
            tx_addr,
        )?;
    }

    srv.listen_loop()
}

impl AppServer {
    pub fn new<A: ToSocketAddrs>(
        sk: SSk,
        pk: SPk,
        addr: A,
        verbosity: Verbosity,
    ) -> Result<Self> {
        Ok(Self {
            crypt: CryptoServer::new(sk, pk),
            sock: UdpSocket::bind(addr)?,
            peers: Vec::new(),
            verbosity,
        })
    }

    pub fn verbose(&self) -> bool {
        matches!(self.verbosity, Verbosity::Verbose)
    }

    pub fn add_peer(
        &mut self,
        psk: Option<SymKey>,
        pk: SPk,
        outfile: Option<String>,
        outwg: Option<WireguardOut>,
        tx_addr: Option<SocketAddr>,
    ) -> Result<AppPeerPtr> {
        let PeerPtr(pn) = self.crypt.add_peer(psk, pk)?;
        assert!(pn == self.peers.len());
        self.peers.push(AppPeer {
            outfile,
            outwg,
            tx_addr,
        });
        Ok(AppPeerPtr(pn))
    }

    pub fn listen_loop(&mut self) -> Result<()> {
        const INIT_SLEEP: f64 = 0.01;
        const MAX_FAILURES: i32 = 10;
        let mut failure_cnt = 0;

        loop {
            let msgs_processed = 0usize;
            let err = match self.event_loop() {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };

            // This should not happen…
            failure_cnt = if msgs_processed > 0 {
                0
            } else {
                failure_cnt + 1
            };
            let sleep = INIT_SLEEP * 2.0f64.powf(f64::from(failure_cnt - 1));
            let tries_left = MAX_FAILURES - (failure_cnt - 1);
            error!(
                "unexpected error after processing {} messages: {:?} {}",
                msgs_processed,
                err,
                err.backtrace()
            );
            if tries_left > 0 {
                error!("reinitializing networking in {sleep}! {tries_left} tries left.");
                std::thread::sleep(self.crypt.timebase.dur(sleep));
                continue;
            }

            bail!("too many network failures");
        }
    }

    pub fn event_loop(&mut self) -> Result<()> {
        let (mut rx, mut tx) = (MsgBuf::zero(), MsgBuf::zero());
        macro_rules! tx_maybe_with {
            ($peer:expr, $fn:expr) => {
                attempt!({
                    let p = $peer.get_app(self);
                    if let Some(addr) = p.tx_addr {
                        let len = $fn()?;
                        self.sock.send_to(&tx[..len], addr)?;
                    }
                    Ok(())
                })
            };
        }

        loop {
            use rosenpass::protocol::HandleMsgResult;
            use AppPollResult::*;
            use KeyOutputReason::*;
            match self.poll(&mut *rx)? {
                SendInitiation(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .initiate_handshake(peer.lower(), &mut *tx))?,
                SendRetransmission(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .retransmit_handshake(peer.lower(), &mut *tx))?,
                DeleteKey(peer) => self.output_key(peer, Stale, &SymKey::random())?,

                ReceivedMessage(len, addr) => {
                    multimatch!(self.crypt.handle_msg(&rx[..len], &mut *tx),
                        Err(ref e) =>
                            self.verbose().then(||
                                info!("error processing incoming message from {:?}: {:?} {}", addr, e, e.backtrace())),

                        Ok(HandleMsgResult { resp: Some(len), .. }) => {
                            self.sock.send_to(&tx[0..len], addr)?
                        },

                        Ok(HandleMsgResult { exchanged_with: Some(p), .. }) => {
                            let ap = AppPeerPtr::lift(p);
                            ap.get_app_mut(self).tx_addr = Some(addr);
                            // TODO: Maybe we should rather call the key "rosenpass output"?
                            self.output_key(ap, Exchanged, &self.crypt.osk(p)?)?;
                        }
                    );
                }
            };
        }
    }

    pub fn output_key(&self, peer: AppPeerPtr, why: KeyOutputReason, key: &SymKey) -> Result<()> {
        let peerid = peer.lower().get(&self.crypt).pidt()?;
        let ap = peer.get_app(self);

        if self.verbose() {
            let msg = match why {
                KeyOutputReason::Exchanged => "Exchanged key with peer",
                KeyOutputReason::Stale => "Erasing outdated key from peer",
            };
            info!("{} {}", msg, fmt_b64(&*peerid));
        }

        if let Some(of) = ap.outfile.as_ref() {
            // This might leave some fragments of the secret on the stack;
            // in practice this is likely not a problem because the stack likely
            // will be overwritten by something else soon but this is not exactly
            // guaranteed. It would be possible to remedy this, but since the secret
            // data will linger in the linux page cache anyways with the current
            // implementation, going to great length to erase the secret here is
            // not worth it right now.
            b64_writer(fopen_w(of)?).write_all(key.secret())?;
            let why = match why {
                KeyOutputReason::Exchanged => "exchanged",
                KeyOutputReason::Stale => "stale",
            };
            println!(
                "output-key peer {} key-file {} {}",
                fmt_b64(&*peerid),
                of,
                why
            );
        }

        if let Some(owg) = ap.outwg.as_ref() {
            let child = Command::new("wg")
                .arg("set")
                .arg(&owg.dev)
                .arg("peer")
                .arg(&owg.pk)
                .arg("preshared-key")
                .arg("/dev/stdin")
                .stdin(Stdio::piped())
                .args(&owg.extra_params)
                .spawn()?;
            b64_writer(child.stdin.unwrap()).write_all(key.secret())?;
        }

        Ok(())
    }

    pub fn poll(&mut self, rx_buf: &mut [u8]) -> Result<AppPollResult> {
        use rosenpass::protocol::PollResult as C;
        use AppPollResult as A;
        loop {
            return Ok(match self.crypt.poll()? {
                C::DeleteKey(PeerPtr(no)) => A::DeleteKey(AppPeerPtr(no)),
                C::SendInitiation(PeerPtr(no)) => A::SendInitiation(AppPeerPtr(no)),
                C::SendRetransmission(PeerPtr(no)) => A::SendRetransmission(AppPeerPtr(no)),
                C::Sleep(timeout) => match self.try_recv(rx_buf, timeout)? {
                    Some((len, addr)) => A::ReceivedMessage(len, addr),
                    None => continue,
                },
            });
        }
    }

    pub fn try_recv(&self, buf: &mut [u8], timeout: Timing) -> Result<Option<(usize, SocketAddr)>> {
        if timeout == 0.0 {
            return Ok(None);
        }
        self.sock
            .set_read_timeout(Some(Duration::from_secs_f64(timeout)))?;
        match self.sock.recv_from(buf) {
            Ok(x) => Ok(Some(x)),
            Err(e) => match e.kind() {
                ErrorKind::WouldBlock => Ok(None),
                ErrorKind::TimedOut => Ok(None),
                _ => Err(anyhow::Error::new(e)),
            },
        }
    }
}
