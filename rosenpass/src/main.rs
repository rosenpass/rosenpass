//! For the main function

use clap::CommandFactory;
use clap::Parser;
use clap_mangen::roff::{roman, Roff};
use log::error;
use rosenpass::cli::CliArgs;
use rosenpass_util::functional::run;
use std::process::exit;

/// Printing custom man sections when generating the man page
fn print_custom_man_section(section: &str, text: &str, file: &mut std::fs::File) {
    let mut roff = Roff::default();
    roff.control("SH", [section]);
    roff.text([roman(text)]);
    let _ = roff.to_writer(file);
}

/// Catches errors, prints them through the logger, then exits
///
/// The bulk of the command line logic is handled inside [crate::cli::CliArgs::run].
pub fn main() {
    // parse CLI arguments
    let args = CliArgs::parse();

    if let Some(shell) = args.print_completions {
        let mut cmd = CliArgs::command();
        clap_complete::generate(shell, &mut cmd, "rosenpass", &mut std::io::stdout());
        return;
    }

    if let Some(out_dir) = args.generate_manpage {
        std::fs::create_dir_all(&out_dir).expect("Failed to create man pages directory");

        let cmd = CliArgs::command();
        let man = clap_mangen::Man::new(cmd.clone());
        let _ = clap_mangen::generate_to(cmd, &out_dir);

        let file_path = out_dir.join("rosenpass.1");
        let mut file = std::fs::File::create(file_path).expect("Failed to create man page file");

        let _ = man.render_title(&mut file);
        let _ = man.render_name_section(&mut file);
        let _ = man.render_synopsis_section(&mut file);
        let _ = man.render_subcommands_section(&mut file);
        let _ = man.render_options_section(&mut file);
        print_custom_man_section("EXIT STATUS", EXIT_STATUS_MAN, &mut file);
        print_custom_man_section("SEE ALSO", SEE_ALSO_MAN, &mut file);
        print_custom_man_section("STANDARDS", STANDARDS_MAN, &mut file);
        print_custom_man_section("AUTHORS", AUTHORS_MAN, &mut file);
        print_custom_man_section("BUGS", BUGS_MAN, &mut file);
        return;
    }

    {
        use rosenpass_secret_memory as SM;
        #[cfg(feature = "experiment_memfd_secret")]
        SM::secret_policy_try_use_memfd_secrets();
        #[cfg(not(feature = "experiment_memfd_secret"))]
        SM::secret_policy_use_only_malloc_secrets();
    }

    // init logging
    {
        let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
        if let Some(level) = args.get_log_level() {
            log::debug!("setting log level to {:?} (set via CLI parameter)", level);
            log_builder.filter_level(level); // set log level filter from CLI args if available
        }
        log_builder.init();

        // // check the effectiveness of the log level filter with the following lines:
        // use log::{debug, error, info, trace, warn};
        // trace!("trace dummy");
        // debug!("debug dummy");
        // info!("info dummy");
        // warn!("warn dummy");
        // error!("error dummy");
    }

    let res = run(|| {
        #[cfg(feature = "internal_signal_handling_for_coverage_reports")]
        let term_signal = terminate::TerminateRequested::new()?;

        let broker_interface = args.get_broker_interface();
        let err = match args.run(broker_interface, None) {
            Ok(()) => return Ok(()),
            Err(err) => err,
        };

        // This is very very hacky and just used for coverage measurement
        #[cfg(feature = "internal_signal_handling_for_coverage_reports")]
        {
            let terminated_by_signal = err
                .downcast_ref::<std::io::Error>()
                .filter(|e| e.kind() == std::io::ErrorKind::Interrupted)
                .filter(|_| term_signal.value())
                .is_some();
            if terminated_by_signal {
                log::warn!(
                    "\
                    Terminated by signal; this signal handler is correct during coverage testing \
                    but should be otherwise disabled"
                );
                return Ok(());
            }
        }

        Err(err)
    });

    if let Err(e) = res {
        error!("{e:?}");
        exit(1);
    }
}

/// Custom main page section: Exit Status
static EXIT_STATUS_MAN: &str = r"
The rosenpass utility exits 0 on success, and >0 if an error occurs.";

/// Custom main page section: See also.
static SEE_ALSO_MAN: &str = r"
rp(1), wg(1)

Karolin Varner, Benjamin Lipp, Wanja Zaeske, and Lisa Schmidt, Rosenpass, https://rosenpass.eu/whitepaper.pdf, 2023.";

/// Custom main page section: Standards.
static STANDARDS_MAN: &str = r"
This tool is the reference implementation of the Rosenpass protocol, as
specified within the whitepaper referenced above.";

/// Custom main page section: Authors.
static AUTHORS_MAN: &str = r"
Rosenpass was created by Karolin Varner, Benjamin Lipp, Wanja Zaeske, Marei
Peischl, Stephan Ajuvo, and Lisa Schmidt.";

/// Custom main page section: Bugs.
static BUGS_MAN: &str = r"
The bugs are tracked at https://github.com/rosenpass/rosenpass/issues.";

/// These signal handlers are used exclusively used during coverage testing
/// to ensure that the llvm-cov can produce reports during integration tests
/// with multiple processes where subprocesses are terminated via kill(2).
///
/// llvm-cov does not support producing coverage reports when the process exits
/// through a signal, so this is necessary.
///
/// The functionality of exiting gracefully upon reception of a terminating signal
/// is desired for the production variant of Rosenpass, but we should make sure
/// to use a higher quality implementation; in particular, we should use signalfd(2).
///
#[cfg(feature = "internal_signal_handling_for_coverage_reports")]
mod terminate {
    use signal_hook::flag::register as sig_register;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    /// Automatically register a signal handler for common termination signals;
    /// whether one of these signals was issued can be polled using [Self::value].
    ///
    /// The signal handler is not removed when this struct goes out of scope.
    pub struct TerminateRequested {
        value: Arc<AtomicBool>,
    }

    impl TerminateRequested {
        /// Register signal handlers watching for common termination signals
        pub fn new() -> anyhow::Result<Self> {
            let value = Arc::new(AtomicBool::new(false));
            for sig in signal_hook::consts::TERM_SIGNALS.iter().copied() {
                sig_register(sig, Arc::clone(&value))?;
            }
            Ok(Self { value })
        }

        /// Check whether a termination signal has been set
        pub fn value(&self) -> bool {
            self.value.load(Ordering::Relaxed)
        }
    }
}
