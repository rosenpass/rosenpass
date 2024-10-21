use clap::CommandFactory;
use clap::Parser;
use clap_mangen::roff::{roman, Roff};
use log::error;
use rosenpass::cli::CliArgs;
use std::process::exit;

fn print_custom_man_section(section: &str, text: &str, file: &mut std::fs::File) {
    let mut roff = Roff::default();
    roff.control("SH", [section]);
    roff.text([roman(text)]);
    let _ = roff.to_writer(file);
}

/// Catches errors, prints them through the logger, then exits
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

    let broker_interface = args.get_broker_interface();
    match args.run(broker_interface, None) {
        Ok(_) => {}
        Err(e) => {
            error!("{e:?}");
            exit(1);
        }
    }
}
static EXIT_STATUS_MAN: &str = r"
The rosenpass utility exits 0 on success, and >0 if an error occurs.";

static SEE_ALSO_MAN: &str = r"
rp(1), wg(1)

Karolin Varner, Benjamin Lipp, Wanja Zaeske, and Lisa Schmidt, Rosenpass, https://rosenpass.eu/whitepaper.pdf, 2023.";

static STANDARDS_MAN: &str = r"
This tool is the reference implementation of the Rosenpass protocol, as
specified within the whitepaper referenced above.";

static AUTHORS_MAN: &str = r"
Rosenpass was created by Karolin Varner, Benjamin Lipp, Wanja Zaeske, Marei
Peischl, Stephan Ajuvo, and Lisa Schmidt.";

static BUGS_MAN: &str = r"
The bugs are tracked at https://github.com/rosenpass/rosenpass/issues.";
