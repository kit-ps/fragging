# Breaking and (Partially) Fixing Onion Routing With Fragmentation

Artifacts:

* Our prototype implementation of Scylla.
* The benchmark code for Nym's Sphinx implementation.
* The Nym testbed to demonstrate the attack.

Usage:

```bash
# Run the Scylla benchmarks:
( cd scylla && cargo bench )
# Generate Scylla onion sizes:
( cd scylla && cargo run --example=onion_sizes --release )
# Run the Sphinx benchmarks:
( cd sphinx-benchmarks && ./run.sh )
# Generate the graphs using the notebook:
jupyter notebook Benchmarks.ipynb
# Use the Nym testbed to test the attack:
./testbed-setup.sh
./testbed-run.sh
```
