# tlscheck

[English](README.md) | [繁體中文](README.zh-TW.md)

A planned Go CLI for inspecting remote TLS certificates and local certificate and private key files.

## Project status

The project is in specification planning. No CLI implementation, Go module, release, or installable package is available yet. Installation, build, and usage instructions will be added when implemented and verified.

The planned scope includes automatic input detection, certificate chain and key pairing checks, English and Chinese terminal messages, and macOS and Windows releases.

## Repository conventions

- `.editorconfig` defines text formatting; `.gitattributes` controls line endings.
- Build and release outputs belong in `bin/` and `dist/`.
- Keep private local certificates and keys in the ignored `local/` directory. Do not commit sensitive material. Certificate and key extensions are not globally ignored so that intentional test fixtures can be tracked.
- Private specifications are maintained outside this repository.
- `make help` lists currently available maintenance commands. GNU Make is optional and is not required to use the future CLI.

## License

[Apache License 2.0](LICENSE).
