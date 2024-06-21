from pathlib import Path
from subprocess import run


config = dict(
    peer_counts=[1, 5, 10, 50, 100, 500],
    peer_count_max=100,
    ate_ip="192.168.2.1",
    dut_ip="192.168.2.4",
    dut_port=9999,
    path_to_rosenpass_bin="/Users/user/src/rosenppass/rosenpass/target/debug/rosenpass",
)

print(config)

output_dir = Path("output")
output_dir.mkdir(exist_ok=True)

template_dut = """
public_key = "keys/dut-public-key"
secret_key = "keys/dut-secret-key"
listen = ["{dut_ip}:{dut_port}"]
verbosity = "Quiet"
"""
template_dut_peer = """
[[peers]] # ATE-{i}
public_key = "keys/ate-{i}-public-key"
endpoint = "{ate_ip}:{ate_port}"
key_out = "out/key_out_{i}"
"""

template_ate = """
public_key = "keys/ate-{i}-public-key"
secret_key = "keys/ate-{i}-secret-key"
listen = ["{ate_ip}:{ate_port}"]
verbosity = "Quiet"

[[peers]] # DUT
public_key = "keys/dut-public-key"
endpoint = "{dut_ip}:{dut_port}"
key_out = "out/key_out_{i}"
"""

(output_dir / "dut" / "keys").mkdir(exist_ok=True, parents=True)
(output_dir / "dut" / "out").mkdir(exist_ok=True, parents=True)
(output_dir / "dut" / "configs").mkdir(exist_ok=True, parents=True)
(output_dir / "ate" / "keys").mkdir(exist_ok=True, parents=True)
(output_dir / "ate" / "out").mkdir(exist_ok=True, parents=True)
(output_dir / "ate" / "configs").mkdir(exist_ok=True, parents=True)

for peer_count in config["peer_counts"]:
    dut_config = template_dut.format(**config)
    for i in range(peer_count):
        dut_config += template_dut_peer.format(**config, i=i, ate_port=50000 + i)

    (output_dir / "dut" / "configs" / f"dut-{peer_count}.toml").write_text(dut_config)

    if not (output_dir / "dut" / "keys" / "dut-public-key").exists():
        print("Generate DUT keys")
        run(
            [
                config["path_to_rosenpass_bin"],
                "gen-keys",
                f"configs/dut-{peer_count}.toml",
            ],
            cwd=output_dir / "dut",
        )
    else:
        print("DUT keys already exist")

# copy the DUT public key to the ATE
(output_dir / "ate" / "keys" / "dut-public-key").write_bytes(
    (output_dir / "dut" / "keys" / "dut-public-key").read_bytes()
)

ate_script = "(trap 'kill 0' SIGINT; \\\n"

for i in range(config["peer_count_max"]):
    (output_dir / "ate" / "configs" / f"ate-{i}.toml").write_text(
        template_ate.format(**config, i=i, ate_port=50000 + i)
    )

    if not (output_dir / "ate" / "keys" / f"ate-{i}-public-key").exists():
        # generate ATE keys
        run(
            [config["path_to_rosenpass_bin"], "gen-keys", f"configs/ate-{i}.toml"],
            cwd=output_dir / "ate",
        )
    else:
        print(f"ATE-{i} keys already exist")

    # copy the ATE public keys to the DUT
    (output_dir / "dut" / "keys" / f"ate-{i}-public-key").write_bytes(
        (output_dir / "ate" / "keys" / f"ate-{i}-public-key").read_bytes()
    )

    ate_script += (
        f"{config['path_to_rosenpass_bin']} exchange-config configs/ate-{i}.toml & \\\n"
    )

    if (i + 1) in config["peer_counts"]:
        write_script = ate_script
        write_script += "wait)"

        (output_dir / "ate" / f"run-{i+1}.sh").write_text(write_script)
