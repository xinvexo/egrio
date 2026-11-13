# Egrio

A native desktop proxy client written in Rust for macOS, Windows and Linux.
Supports Clash YAML profiles and subscriptions. The proxy core can also be
used independently of the desktop app.

## Supported Protocols

- HTTP / HTTPS proxy
- SOCKS5
- Shadowsocks (AEAD and AEAD 2022)
- Trojan
- Hysteria2
- OpenVPN (client)

See [protocol support and limitations](docs/architecture/core.md#模块布局)
for supported options.

## Development

Use the Rust toolchain pinned in `rust-toolchain.toml` and install the
platform prerequisites:

- [macOS](docs/platforms/macos.md): Xcode command line tools.
- [Windows](docs/platforms/windows.md): MSVC and Windows App Runtime 2.x;
  run `cargo xtask windows-deps` before building.
- [Linux](docs/platforms/linux.md): GTK 4 and libadwaita development files
  (`libgtk-4-dev` and `libadwaita-1-dev` on Ubuntu).

```sh
cargo build -p egrio
cargo xtask check
```

For development runs, set `EGRIO_DATA_DIR` to an empty directory and leave
capture off. See [the engineering guide](AGENTS.md) for more commands.

## Documentation

[Documentation map](docs/README.md) ·
[Architecture](docs/architecture/overview.md) ·
[Known issues](docs/backlog.md)

## License

[GNU GPL v3.0 only](LICENSE) (`GPL-3.0-only`).
