## What and why

<!-- What changes, and the problem it solves. Link the issue if there is one. -->

## Testing

<!-- Tick what you ran. CI runs all of these too, as root. -->

- [ ] `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `sudo ./target/release/bpfrag --selftest` (if the BPF programs changed)
- [ ] `sudo tests/rig/e2e.sh target/release/bpfrag` (if detection, tuning or restore changed)
- [ ] Tried in a real match (game, and Ethernet or Wi-Fi):

## Checklist

- [ ] Networking or writeback only: nothing touches CPU scheduling, frequency or IRQ affinity.
- [ ] New settings are journalled before they change, and restored without overwriting changes made by someone else (see AGENTS.md).
- [ ] New or renamed flags are in `dist/bpfrag.8`.
- [ ] Builds on Rust 1.85 (no let-chains).
- [ ] No code from Oracle's bpftune.
