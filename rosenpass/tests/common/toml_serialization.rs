use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

fn toml_des<S: Borrow<str>>(s: S) -> Result<toml::Table, toml::de::Error> {
    toml::from_str(s.borrow())
}

fn toml_ser<S: Serialize>(s: S) -> Result<toml::Table, toml::ser::Error> {
    toml::Table::try_from(s)
}

fn assert_toml<L: Serialize, R: Borrow<str>>(l: L, r: R, info: &str) -> anyhow::Result<()> {
    fn lines_prepend(prefix: &str, s: &str) -> anyhow::Result<String> {
        use std::fmt::Write;

        let mut buf = String::new();
        for line in s.lines() {
            writeln!(&mut buf, "{prefix}{line}")?;
        }
        Ok(buf)
    }

    let l = toml_ser(l)?;
    let r = toml_des(r.borrow())?;
    anyhow::ensure!(
        l == r,
        "{}{}TOML value mismatch.\n  Have:\n{}\n  Expected:\n{}",
        info,
        if info.is_empty() { "" } else { ": " },
        lines_prepend("    ", &toml::to_string_pretty(&l)?)?,
        lines_prepend("    ", &toml::to_string_pretty(&r)?)?
    );
    Ok(())
}

pub fn assert_toml_round<'de, L: Serialize + Deserialize<'de>, R: Borrow<str>>(
    l: L,
    r: R,
) -> anyhow::Result<()> {
    let l = toml_ser(l)?;
    assert_toml(&l, r.borrow(), "Straight deserialization")?;

    let l: L = l.try_into().unwrap();
    let l = toml_ser(l).unwrap();
    assert_toml(l, r.borrow(), "Roundtrip deserialization")?;

    Ok(())
}
