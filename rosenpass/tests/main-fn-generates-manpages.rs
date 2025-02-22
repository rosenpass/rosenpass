use rosenpass_util::functional::ApplyExt;

fn expect_section(manpage: &str, section: &str) -> anyhow::Result<()> {
    anyhow::ensure!(manpage.lines().any(|line| { line.starts_with(section) }));
    Ok(())
}

fn expect_sections(manpage: &str, sections: &[&str]) -> anyhow::Result<()> {
    for section in sections.iter().copied() {
        expect_section(manpage, section)?;
    }
    Ok(())
}

fn expect_contents(manpage: &str, patterns: &[&str]) -> anyhow::Result<()> {
    for pat in patterns.iter().copied() {
        anyhow::ensure!(manpage.contains(pat))
    }
    Ok(())
}

fn filter_backspace(str: &str) -> anyhow::Result<String> {
    let mut out = String::new();
    for chr in str.chars() {
        if chr == '\x08' {
            anyhow::ensure!(out.pop().is_some());
        } else {
            out.push(chr);
        }
    }
    Ok(out)
}

/// Spot tests about man page generation; these are by far not exhaustive.
#[test]
fn main_fn_generates_manpages() -> anyhow::Result<()> {
    let dir = tempfile::TempDir::with_prefix("rosenpass-test-main-fn-generates-mangapges")?;
    let cmd_out = test_bin::get_test_bin("rosenpass")
        .args(["--generate-manpage", dir.path().to_str().unwrap()])
        .output()?;
    assert!(cmd_out.status.success());

    let expected_manpages = [
        "rosenpass.1",
        "rosenpass-exchange.1",
        "rosenpass-exchange-config.1",
        "rosenpass-gen-config.1",
        "rosenpass-gen-keys.1",
        "rosenpass-validate.1",
    ];

    let man_texts: std::collections::HashMap<&str, String> = expected_manpages
        .iter()
        .copied()
        .map(|name| (name, dir.path().join(name)))
        .map(|(name, path)| {
            let res = std::process::Command::new("man").arg(path).output()?;
            assert!(
                res.status.success(),
                "Error rendering manpage {name} using man"
            );
            let body = res
                .stdout
                .apply(String::from_utf8)?
                .apply(|s| filter_backspace(&s))?;
            Ok((name, body))
        })
        .collect::<anyhow::Result<_>>()?;
    for (name, body) in man_texts.iter() {
        expect_sections(body, &["NAME", "SYNOPSIS", "OPTIONS"])?;

        if *name != "rosenpass.1" {
            expect_section(body, "DESCRIPTION")?;
        }
    }

    {
        let body = man_texts.get("rosenpass.1").unwrap();
        expect_sections(
            body,
            &["EXIT STATUS", "SEE ALSO", "STANDARDS", "AUTHORS", "BUGS"],
        )?;
        expect_contents(
            body,
            &[
                "[--log-level]",
                "rosenpass-exchange-config(1)",
                "Start Rosenpass key exchanges based on a configuration file",
                "https://rosenpass.eu/whitepaper.pdf",
            ],
        )?;
    }

    {
        let body = man_texts.get("rosenpass-exchange.1").unwrap();
        expect_contents(body, &["[-c|--config-file]", "PSK := preshared-key"])?;
    }

    Ok(())
}
