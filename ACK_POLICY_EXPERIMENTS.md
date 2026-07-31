# Experimental receiver ACK policies

This branch adds two implementation-derived receiver ACK policies for controlled
QUIC experiments. They affect Application Data packet number spaces only;
Initial and Handshake packets continue to be acknowledged immediately.

| Policy | 1-RTT ACK behavior |
| --- | --- |
| QUICHE | ACK every 2 ACK-eliciting packets initially. Once the packet number space advances by 100 from the first observed packet, ACK every 10 packets. The delayed-ACK timer becomes `max(1 ms, min(25 ms, min_rtt / 4))`. |
| Neqo | ACK every 2 ACK-eliciting packets, delay at most 20 ms, and immediately acknowledge observable reordering. |

These policies abstract the principal locally observable signals. They are not
byte-for-byte ports and intentionally exclude peer-controlled `ACK_FREQUENCY`
and `IMMEDIATE_ACK` behavior.

Reference implementations:

- Google QUICHE commit `38097a7a48d5f7d0853ec0ece88269c08283c9c7`
- Mozilla Neqo commit `e2a2a7459b8b51778b50209251a61fc5ca020893`
- quic-go upstream base `9bfbf4cd052b5927e6ba31f2376493f057b1142e`

## Public API

Set `quic.Config.ACKPolicy` to one of:

```go
quic.ACKPolicyDefault
quic.ACKPolicyQUICHE
quic.ACKPolicyNeqo
```

The zero value preserves quic-go's default behavior.

## Experiment client

Build the dedicated client without changing quic-go's general-purpose example:

```sh
go build -o quic-go-policy-client ./example/ack-policy-client
```

Example:

```sh
./quic-go-policy-client \
  -url https://127.0.0.1:4433/1GB.bin \
  -insecure \
  -ack-policy quiche \
  -local-port 54433 \
  -start-at-unix-ns 1780000000000000000 \
  -timeout 60s \
  -metrics metrics.csv
```

The client can optionally emit qlog with `-qlog-dir`. Duration-limited body
timeouts are treated as normal completion so that metrics are flushed.
