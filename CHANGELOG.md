# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Semantic versioning script `deploy/version.sh` deriving versions from git tags and commit history.
- Unauthenticated `GET /healthz` endpoint returning application status and version.
- Build-time `PULSE_VERSION` build argument and standard OCI image labels (`version`, `revision`, `source`) in `Dockerfile`.
- Visible application version in the page footer for authenticated operators.

