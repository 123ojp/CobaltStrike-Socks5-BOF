# Changelog

## Unreleased

### Added

- `WRITE_READ` (op `7`): sends client data and returns any server data in the
  same BOF task. The relay uses it so each RDP request/response exchange costs
  one task instead of two.
- `--reset-on-start` and `--reset-on-exit` to clean stale BOF streams.
- Windows `SIGBREAK` handling; Ctrl+C now stops the child orchestrator instead
  of leaving it running.

### Changed

- `MAX_CHUNK` raised to 32768 bytes; READ drains the socket buffer so a
  multi-segment response can arrive in one task.
- `TCP_NODELAY` enabled on the target socket and the orchestrator's client
  socket.
- Removed the 25 ms read-coalescing delay.
- RDP X.224 through the task pump measured ~1.98 s in the test environment,
  down from ~4.46 s on the earlier build.

### Documentation

- Documented the Beacon task check-in floor (~1 s even at `sleep=0`) and why
  REST polling is not the bottleneck.
- Added a comparison with native pivots, thread/process-based BOF proxies,
  async BOF/PICO frameworks, and separate tunnels.
- Corrected the RDP guidance and replaced lab-specific IPs, passwords, and
  Beacon identifiers in the public documents with placeholders.
