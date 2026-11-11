# Bounded live verification

On November 11, 2026, a disposable kind Kubernetes cluster exercised the operator with synthetic traffic. This is a development test, not a production or performance claim.

The operator created a Deployment using an existing PVC containing a synthetic DNS PCAP. Suricata 8.0.8 processed the capture and emitted the expected alert, signature 9000001. The same operator created a host-network live-capture DaemonSet using NET_RAW and NET_ADMIN, without privileged mode; synthetic UDP traffic generated alert 9000002. An optional metrics Service was created with a stub exporter, so actual exporter output was not established.

For file extraction, the operator mounted an existing writable PVC into a Deployment. With Suricata file-store configuration and an extraction rule supplied for a synthetic HTTP capture, the pod wrote a file whose SHA-256 matched the test fixture: `8f8d3c41a7f807fc737f381f145a6a825ad69e96a5719b1d23ae5814b23f679f`. The operator does not itself enable file-store or create the PVC.

The configuration-backup utility also exported and restored a test sensor using the disposable cluster. That operation covers sensor spec and referenced ConfigMaps, not PVC contents or Secrets.

A separate disposable kind cluster exercised opt-in native Suricata 8.0.8 AF_PACKET inline IPS. The operator created a host-network DaemonSet with two dedicated veth interfaces and symmetric `copy-mode: ips` configuration. Two isolated network namespaces sent `ALLOWME` and `BLOCKME` UDP payloads through that pair: the receiver obtained only `ALLOWME`, and EVE recorded signature 9000401 as `blocked`. The traffic and interfaces were confined to the disposable kind node; the sender disabled UDP checksums for the synthetic veth fixture. This establishes that particular configured path, not an automatic bypass or fail-safe.

The inline tests alone do not establish XDP enforcement; the separate narrow XDP cache test is described below. The exercises do not establish production traffic capture, automatic rule reload, distributed operation, actual metrics exporter output, or performance. Synthetic test artifacts and logs were retained locally under `/tmp/yas-live`; no production capture is included in this repository.

## Experimental XDP verdict cache

A separate disposable kind-node test used the operator-generated inline DaemonSet with a real XDP verdict sidecar. With the cache disabled, the receiver saw `ALLOW0` and `CACHED` after a separate `BLOCKME` packet was blocked by Suricata. With the cache enabled and a three-second TTL, a matching flow delivered `ALLOW0`, did not deliver `BLOCKME` or the subsequent `CACHED`, delivered `OTHER` on a different source port, and delivered `EXPIRED` after four seconds. The first blocked packet produced an actual EVE alert, and an isolated diagnostic prototype observed one XDP-map hit. The interfaces and traffic were confined to test network namespaces on the disposable node. This verifies only that IPv4 UDP scenario, not all traffic, failure modes, or production performance.
