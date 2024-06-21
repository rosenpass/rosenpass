# Additional files

This folder contains additional files that are used in the project.

## `generate_configs.py`

The script is used to generate configuration files for a benchmark setup
consisting of a device under testing (DUT) and automatic test equipment (ATE),
basically a strong machine capable of running multiple Rosenpass instances at
once.

At the top of the script multiple variables can be set to configure the DUT IP
address and more. Once configured you may run `python3 generate_configs.py` to
create the configuration files.

A new folder called `output/` is created containing the subfolder `dut/` and
`ate/`. The former has to be copied on the DUT, ideally reproducible hardware
like a Raspberry Pi, while the latter is copied to the ATE, i.e. a laptop.

### Running a benchmark

On the ATE a run script is required since multiple instances of `rosenpass` are
started with different configurations in parallel. The scripts are named after
the number of instances they start, e.g. `run-50.sh` starts 50 instances.

```shell
# on the ATE aka laptop
cd output/ate
./run-10.sh
```

On the DUT you start a single Rosenpass instance with the configuration matching
the ATE number of peers.

```shell
# on the DUT aka Raspberry Pi
rosenpass exchange-config configs/dut-10.toml
```

Use whatever measurement tool you like to monitor the DUT and ATE.
