# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.1] - 2026-07-19

### Tests
- **resolver:** Cover the `ResolvesServerCert` serving hot path with a real in-memory TLS handshake — asserts `load_server_config` presents the on-disk leaf and that `reload()` hot-swaps the served leaf (resolver.rs line coverage 79% → 92%).

## [0.1.0] - 2026-07-16

### Features
- **dig-cert:** Per-machine name-constrained local TLS CA + leaf issuance + auto-renewal (#1)


