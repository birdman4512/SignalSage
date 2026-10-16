# Changelog

All notable changes to SignalSage are documented here.

The format follows Keep a Changelog and releases use semantic versioning.

## Unreleased

### Added

- Startup validation for application and digest configuration.
- Versioned SQLite schema migrations.
- JSON logging, health/readiness endpoints, and runtime metrics endpoint.
- Supervision with bounded restart backoff for platform connections.
- Installable package metadata and a `signalsage` console command.

### Changed

- Production and development dependencies are reproducibly pinned.
