# Project Engineering Rules

Egrio: a reusable Rust proxy core (`egrio-core`), platform capture
adapters, a non-GUI daemon/service runtime, and a native desktop app written
in Rust (`desktop/`: the product backend, the interface described once in
`egrio-ui`, and the `egrio` app with AppKit, WinUI 3 and GTK 4 backends). The
crates must stay usable without the desktop app.

This project has no legacy-compatibility burden. When a better architecture
is needed, refactor directly and remove obsolete compatibility layers instead
of building around them.

## Commands

- `cargo run -p egrio` — the desktop app (on Windows run
  `cargo xtask windows-deps` first and have the Windows App Runtime 2.x
  installed; on Linux it builds against GTK 4 and libadwaita,
  `libgtk-4-dev` and `libadwaita-1-dev` on Ubuntu). `--features test-control`
  adds the local control socket; set `EGRIO_DATA_DIR` to an empty directory so
  a development instance never shares data with the installed app, and do not
  turn capture on in it.
- `cargo xtask check` — the static gate every commit passes: the xtask
  tests, the workspace dependency and macOS contract checks,
  `cargo fmt --check`, all-target `cargo check` of the workspace, the
  server-only daemon and the Core with the `server` feature, and
  `cargo xtask docs`.
- `cargo xtask check --full` — the static gate, then
  `cargo test --workspace`, the Core and daemon tests with the `server`
  role, the SDK tests under each desktop platform feature, and
  `git diff --check`.
- `cargo xtask docs` — the documentation map, links, anchors and format
  rules; `cargo xtask bench-compare <baseline> <candidate>` compares two
  Core throughput benchmark runs on one host.
- `cargo xtask package` — build the app's package for this machine's
  platform. On a Mac: the signed `Egrio.app` (its signature, the service's
  team, the launchd property list and the service checked before anything
  registers it) and a signed DMG, under `target/<triple>/release/bundle/`.
  `--notarize <keychain profile>` also notarizes and staples both;
  `--identity` and `--target` choose the signing identity and the target.
  `--test-control` builds an acceptance app instead (signed the same way,
  so the service accepts it, with the test control socket) under
  `target/test-control/`; it is never notarized or shipped. On Windows: the
  NSIS installer `Egrio_<version>_x64-setup.exe` under
  `target/x86_64-pc-windows-msvc/release/bundle/nsis/`, with a pinned NSIS
  it fetches itself. On x86_64 Linux: the Ubuntu deb,
  `target/release/bundle/deb/egrio_<version>_amd64.deb`, which fails when
  either binary needs a glibc symbol newer than the package's
  `libc6 (>= 2.39)`; release debs are built on Ubuntu 24.04 with
  `libgtk-4-dev`, `libadwaita-1-dev`, `binutils` and `dpkg`.
- Pushing the tag `v<version>` (the workspace's version) runs
  `.github/workflows/release.yml`, which packages every platform and
  publishes a GitHub release the app's update check reads; push a tag only
  when asked to release ([release runbook](docs/runbooks/release.md)).
- `cargo xtask icons` — render the icon artwork in `design/icons` into the
  icons the app carries (`desktop/egrio/icons`).
- `cargo xtask windows-deps` — fetch the pinned Windows App SDK packages and
  Wintun and stage the bootstrapper DLL and `wintun.dll` beside the Windows
  builds (any host); `--bindings` also regenerates
  `desktop/egrio/src/windows/bindings.rs` from `bindings.txt`.
- `cargo test -p <crate>` runs one crate's tests. The repository needs only
  the Rust toolchain.

## Documentation

[`docs/README.md`](docs/README.md) is the document map and holds the
documentation rules. Documents describe only the current code and product;
history lives in Git, so finished designs are deleted rather than archived.

Every kind of fact has exactly one home. Update the owning document in the
same commit as the code change; other documents link to it instead of
restating. A document that contradicts the code is a bug — question it, then
fix whichever side is wrong.

Before implementing or refactoring, classify the change against the
architecture and platform documents. Open work, known defects, and unverified
scope live in [`docs/backlog.md`](docs/backlog.md); delete an item when it is
done. After a system validation, replace the platform document's validation
status and move unfixed findings into the backlog. Follow the
[capture-layer runbook](docs/runbooks/capture-layers.md) for capture
validation.

## Architecture Rules

- Prefer clean, standard, responsibility-based modules over large mixed files.
- For an intentional architecture replacement, perform a direct cutover: do
  not preserve historical baggage, decorate the old implementation, or add a
  temporary compatibility layer just to avoid deleting it. Rename and
  restructure the ownership boundaries, remove obsolete code and tests, and
  keep one production path unless an explicit product requirement calls for
  parallel implementations.
- Do not add code just to grow the codebase. Every implementation batch must
  produce a verifiable capability, remove real complexity, or establish a
  required platform/core boundary with tests or documented checks.
- Keep platform-specific implementations in platform directories such as
  `macos`, `windows`, and `linux`.
- Platform code is split first by capability and then by OS backend:
  platform-crate `packet_capture` modules own the platform TUN device and its
  packet lifecycle, `system_proxy` modules own optional proxy-settings
  compatibility, and firewall modules own kill-switch enforcement plans.
  the macOS utun, Windows Wintun, and Linux `/dev/net/tun` are separate
  implementations of the same packet-capture boundary; flow-level Transparent
  Proxy and Linux TPROXY are not production capture backends.
  Shared contracts stay in module roots.
- Extract shared contracts, models, IPC, and lifecycle helpers into shared
  modules only when they are genuinely platform-independent.
- Do not use `apple` as a platform bucket. Use `macos` for macOS-specific
  code.
- UI code must not own long-running networking state. Native/service layers
  own capture, routing, firewall, cleanup, recovery, and provider lifecycle.

## Platform Work

- Platform APIs must be implemented from official documentation, SDK headers,
  or vendor-maintained references. Do not implement platform behavior from
  memory.
- Record the official source or SDK basis in docs when adding platform-level
  behavior.
- If a platform API or entitlement value cannot be verified, leave a clearly
  marked placeholder or documentation note instead of presenting it as done.
- Different platform implementations should live separately and meet at a
  small common contract.
- Windows WFP work may use documented WFP capabilities that do not require
  this project to ship a signed driver or kernel component. Current supported
  scope includes FWPM/BFE management APIs, built-in filtering layers, dynamic
  sessions, providers/sublayers, filters, supported conditions, and read-only
  net-event diagnostics. Do not design or implement WFP callout drivers,
  kernel classify paths, packet modification/injection, or anything that
  depends on Windows driver signing. If a behavior cannot be expressed
  without a new signed driver, document it as unsupported/blocked instead of
  assuming a driver will be available.
- Before an installation or test that changes proxy settings, routes, DNS,
  interfaces, firewall rules, or launchd/service registrations, describe its
  network effects. Keep cleanup able to complete if connectivity is interrupted and
  verify the resulting network state. Do not store credentials in tracked files.

## Change Hygiene

- Keep each coherent feature, fix, or refactor in its own commit.
- Before committing, fetch the upstream branch and integrate remote changes
  if it has advanced, so conflicts are resolved before the local commit is
  made.
- Run the relevant checks before each commit.
- After a successful commit, push the current branch to its upstream unless
  the user explicitly says not to.
- Stage only files that belong to the current change.
- Avoid compatibility aliases for renamed internal APIs unless there is an
  explicit product requirement.
