# Breaking and (Partially) Fixing Onion Routing With Fragmentation 🧩

This repository contains the code we've used to evaluate the Fragging attack
and Scylla from our PETS 2026 paper.

> [!note]
> There is a separate `ARTIFACT-APPENDIX.md` file for the PETS artifact review.

Artifacts:

* Our prototype implementation of Scylla.
* The benchmark code for Nym's Sphinx implementation.
* The Nym testbed to demonstrate the attack.
* Our Jupyter notebook which generates the graphs

## Scylla prototype implementation

Requirements: Rust

Our prototype implementation of Scylla lives in `scylla/`. It uses the standard
Rust package manager (`cargo`) to build, and uses the `criterion` crate for
benchmarks. You can run them via

```bash
cd scylla
# Will take some time:
cargo bench
```

**For Linux:**
In order to make the measurements more stable, it is advised to set your CPU
governor to `performance` and pin the benchmark to a specific core:

```bash
cpupower frequency-set -g performance
# Instead of cargo bench:
taskset -c 0 cargo bench
```

Additionally, we provide an "example" binary which outputs onion sizes as CSV:

```bash
cd scylla
cargo run --release --example=onion_sizes >onion_sizes.csv
```

## Sphinx benchmarks

Requirements: Rust

The Sphinx benchmarks were done with the code in `sphinx-benchmarks/`. The code
is taken from the Nym project (https://github.com/nymtech/sphinx), slightly
adapted to allow for different maximum path lengths to be supplied. We have
preserved the original LICENSE and README.

We provide a script to easily run benchmarks for different parameters:

```bash
cd sphinx-benchmarks
# Will take some time:
./run.sh
```

**For Linux:**
In order to make the measurements more stable, it is advised to set your CPU
governor to `performance` and pin the benchmark to a specific core:

```bash
cpupower frequency-set -g performance
taskset -c 0 ./run.sh
```

## Nym testbed

Requirements: Rust, shadow (https://shadow.github.io/), Python

We provide the testbed we use for the evaluation of Fragging in Nym in
`testbed.patch`. It applies to commit
`f8317f5a03bd5d7fb5a66f53730b00aeb03484a7` of the Nym repository
(https://github.com/nymtech/nym).

In addition, we provide two scripts: `testbed-setup.sh` prepares the source
directory with the patch applied, and `testbed-run.sh` then runs the
experiments:

```bash
./testbed-setup.sh
# Will take some time:
./testbed-run.sh
```

## Jupyter notebook

Requirements: Python with Jupyter notebook and matplotlib

We provide the Jupyter notebook we have used for graph generation as
`Benchmarks.ipynb`. After running the previous steps, the notebook will
automatically read the results from the benchmarks/the testbed:

```bash
jupyter notebook Benchmarks.ipynb
# Run -> Run All Cells
```

# License

The code in `sphinx-benchmarks` is taken from
[Nym](https://github.com/nymtech/sphinx) and has its original license retained.

The remaining code is under the MIT license (see `LICENSE`).
