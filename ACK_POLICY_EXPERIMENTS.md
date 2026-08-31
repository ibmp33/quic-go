# Experimental receiver ACK policies

This branch adds two implementation-derived receiver ACK policies for controlled
QUIC experiments. They affect Application Data packet number spaces only;
Initial and Handshake packets continue to be acknowledged immediately.

| Policy | 1-RTT ACK behavior |
| --- | --- |
| `chrome-like-ack` v1.0.0 | ACK every 2 ACK-eliciting packets initially. On an ACK-instigating packet satisfying `pn >= least_observed_pn + 100`, transition once to threshold 10. The delayed-ACK timer becomes `max(1 ms, min(25 ms, min_rtt / 4))`. Includes the pinned QUICHE missing-packet, new-gap-window, and ECN-CE-transition immediate rules. |
| `neqo-like-ack` v1.0.0 | ACK every 2 ACK-eliciting packets, delay at most 20 ms (also capped by one smoothed RTT since the last ACK), and immediately acknowledge an ACK-eliciting packet whose PN is not next in order. No autonomous threshold transition. |

These are modeled policies, not byte-for-byte ports and not claims of
Firefox/Chrome equivalence. Peer-controlled `ACK_FREQUENCY` is disabled in the
main comparison and remains a separate, explicit interoperability treatment.

Reference implementations:

- Google QUICHE commit `38097a7a48d5f7d0853ec0ece88269c08283c9c7`
- Mozilla Neqo commit `e2a2a7459b8b51778b50209251a61fc5ca020893`
- quic-go upstream base `9bfbf4cd052b5927e6ba31f2376493f057b1142e`

## Public API

Set `quic.Config.ACKPolicy` to one of:

```go
quic.ACKPolicyChromeLike
quic.ACKPolicyNeqoLike
```

The zero value preserves quic-go's default behavior.
`synthetic-fixed-ack-2` and `synthetic-fixed-ack-10` remain available only as
debug/mechanism controls and are not named or reported as browser-like policies.

## Experiment client

Build the dedicated client without changing quic-go's general-purpose example:

```sh
go build -o quic-go-policy-client ./example/ack-policy-client
```

HTTP/3 remains the default protocol. Existing commands continue to work:

```sh
./quic-go-policy-client \
  -protocol http3 \
  -url https://127.0.0.1:4433/1GB.bin \
  -insecure \
  -ack-policy chrome-like-ack \
  -ack-policy-log ack-policy-events.jsonl \
  -local-port 54433 \
  -start-at-unix-ns 1780000000000000000 \
  -duration 60s \
  -metrics metrics.csv
```

For an mvfst `tperf` server, select raw QUIC and pass a UDP address instead of
a URL:

```sh
./quic-go-policy-client \
  -protocol raw \
  -addr 127.0.0.1:6666 \
  -insecure \
  -ack-policy synthetic-fixed-ack-10 \
  -duration 60s \
  -metrics metrics.csv
```

Raw mode negotiates the `quic_test` ALPN, sends no HTTP request, and reads all
server-initiated unidirectional streams. Metrics count bytes across all streams.
If `-o` is set, concurrently received stream chunks are serialized into that
single output file without adding framing or stream boundaries.

Both modes can optionally emit qlog with `-qlog-dir`. Duration-limited reads are
treated as normal completion so that metrics are flushed.
