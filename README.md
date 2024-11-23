# strata-bridge-poc

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/strata-bridge-poc/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/strata-bridge-poc/actions)

PoC Implementation of the Strata Bridge.

> [!IMPORTANT]
> Majority of this code was written in a two-week period in a hackathon spirit.
> This is pre-alpha software that is _not_ meant to be used in a production environment.

## Transaction Graph

The following is the transaction graph that has been implemented in this repo.

<figure>
    <img src="./assets/poc-tx-graph.jpg" alt = "poc tx graph" />
    <figcaption>The Transaction Graph for this PoC focussing on the non-optimistic path.</figcaption>
</figure>

## System Diagram

The following is the system diagram in the PoC:

<figure>
    <img src="./assets/system-design.jpg" alt = "poc system design" />
    <figcaption>System diagram for this PoC.</figcaption>
</figure>

## How To Run Locally

### Pre-requisites

-   SP1 Toolchain and associated linkers.
-   Credentials to connect to SP1's infra.
-   Docker.
-   `sqlx-cli` to run migrations.

### Running

Run the strata stack (`strata-client`, `strata-reth`, `bitcoind`) as per the instructions
in the [`strata`](https://github.com/alpenlabs/strata/tree/bitvm2) repo. Then run:

```bash
make migrate
PROFILE=release make run
```

In order to perform deposits and withdrawals, you can run:

```bash
make bridge-in
make bridge-out
```

The above `Makefile` recipes have defaults for the `strata-client` and `bitcoind`.

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
