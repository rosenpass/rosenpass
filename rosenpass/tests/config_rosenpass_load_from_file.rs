use anyhow::anyhow;
use rosenpass::config::ResolvePathRelativeToConfig;

#[test]
fn example_config_rosenpass_load_from_file() {
    // read config file from disk
    let file_path = PathBuf::from("path/to/config.toml");
    let toml_file = std::fs::read(&file_path).unwrap();
    let toml_file = String::from_utf8(toml_file).unwrap();

    // parse bytes into TOML
    let toml_file = toml_edit::Document::parse(toml_file).unwrap();

    // parse TOML into RosenpassConfig
    let (config, warnings) = RosenpassConfig::parse_from_toml(&toml_file, &file_path).unwrap();

    // resolve a key's absolute file path
    let relative_secret_key_path = config.our_keypair.secret_key_source.get_secret_key_path();
    let absolute_secret_key_path = config.resolve_path(&relative_secret_key_path);
}
