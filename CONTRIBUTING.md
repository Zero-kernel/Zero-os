# Contributing to Nilix

Thanks for your interest in Nilix — a security-first hybrid microkernel written in
Rust for x86_64. This guide gets you from a fresh clone to a green local check run
and a pull request. For an architectural tour, see the [README](README.md).

**Design principle:** Security > Correctness > Efficiency > Performance. When a
change trades safety for speed, safety wins; aggressive restructuring is welcome
when it removes a hazard.

---

## 1. Development environment

Everything builds and runs on Linux (CI uses `ubuntu-latest`); macOS and WSL with
the toolchain installed work too.

- **Rust** — the nightly toolchain is pinned in `rust-toolchain.toml` (with
  `rust-src` + `llvm-tools-preview` and the `x86_64-unknown-none` /
  `x86_64-unknown-uefi` targets; `rustup` installs them automatically). Clippy and
  rustfmt are **not** pinned — add them once:
  ```bash
  rustup component add clippy rustfmt
  ```
- **QEMU + OVMF** — `qemu-system-x86_64` and the OVMF UEFI firmware (for boot/run).
- **GNU Make**.
- **musl toolchain** — `musl-tools` (`musl-gcc`), only for the musl conformance gate.

On Debian/Ubuntu the non-Rust deps match what CI installs:
```bash
sudo apt-get install -y qemu-system-x86 ovmf musl-tools make
```

> Maintainer note: the project is also developed from a Windows mirror that has **no**
> local Rust toolchain and offloads builds to a Linux host. That setup is described in
> §4 — contributors do not need it.

---

## 2. Build & run

```bash
make build           # build bootloader + kernel into the EFI System Partition (esp/)
make run-serial      # run in QEMU with the serial console on your terminal
make run             # run in QEMU (graphical VGA window)
make run-smp         # multi-core boot (SMP_CPUS=N, default 2)
make help            # full target list
```

See [README §4](README.md#4-build-and-run) for the complete list.

---

## 3. Checks (run these before pushing — they are exactly what CI gates)

| Command | What it checks |
|---------|----------------|
| `make fmt-check` | `cargo fmt --check` across the workspace + userspace |
| `make clippy`    | clippy across all three build units (deny-by-default correctness) |
| `make lint`      | grep-based source gates (println, SMAP, fetch_add, repr(C) copies) |
| `make boot-check`| boots the kernel under QEMU; asserts zero NX-violation page faults |
| `make musl-check`| static-musl libc conformance gate |

CI (`.github/workflows/ci.yml`) runs these directly — there is no hidden remote
machinery. If they pass locally, CI should be green.

---

## 4. Pre-push hooks (optional, but recommended — pick **one**)

The repo ships two ways to run `fmt-check` + `clippy` automatically before each
push. They are **mutually exclusive**: enabling the shell hook points Git's
`core.hooksPath` away from `.git/hooks`, where the pre-commit framework installs —
so only one mechanism can be active at a time.

### Option A — shell hook (no extra dependencies)

```bash
make hooks      # sets core.hooksPath=.githooks
```

`.githooks/pre-push` is **local-first**: it runs the checks locally when a Rust
toolchain is present, offloads over SSH when one is configured (see below),
otherwise warns and leaves enforcement to CI. Bypass a single push with
`SKIP_PREPUSH=1 git push`.

### Option B — pre-commit framework

```bash
pip install pre-commit
git config --unset core.hooksPath 2>/dev/null || true   # only if you ran `make hooks` before
pre-commit install                  # wires the pre-commit + pre-push stages
```

Runs `make fmt-check` at commit time and `make clippy` at push time
(`.pre-commit-config.yaml`). Bypass with `git push --no-verify` (or `SKIP=clippy
git push`). If `core.hooksPath` is still set to `.githooks`, Git ignores
`.git/hooks` and this hook silently won't run — unset it first.

### Remote offload (toolchain-less mirror only)

If you develop on a machine with no local toolchain, the shell hook can run the
checks on a remote build host instead. Configure **both**:

```bash
git config zeroos.remote     <ssh-host-alias>
git config zeroos.remoteDir  <repo-path-on-that-host>
```

(`ZEROOS_REMOTE` / `ZEROOS_REMOTE_DIR` env vars override these.) Caveat: offload
validates the **remote** working tree — keep it in sync with your local tree
before pushing.

---

## 5. Coding standards

- `no_std` throughout the kernel; match the style, naming, and comment density of
  the surrounding code.
- The custom lints (`make lint`) are not optional — they reject ungated `println!`,
  unminimized SMAP windows, bare `fetch_add(1)` on IDs/refcounts, and unannotated
  `#[repr(C)]` user-boundary copies. Add the documented `// lint-…: allow` escape
  hatch only with a clear reason.
- New features need documentation updates; bug fixes should include a regression
  test (the kernel runs in-kernel self-tests on boot).

---

## 6. Commit & pull-request flow

1. Branch from `main`; keep each change focused.
2. Run `make build`, `make lint`, `make boot-check`, and (for ABI changes)
   `make musl-check` before pushing.
3. Open a PR against `main`. All four CI jobs (fmt/clippy, build, lint, boot+musl)
   must pass.
4. Commits are **manual** — nothing is auto-committed or auto-pushed.

Welcome aboard, and thanks for helping make Nilix better.
