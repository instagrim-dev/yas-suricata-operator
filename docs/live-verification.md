# Bounded live verification

On November 11, 2026, a disposable kind Kubernetes cluster exercised the operator with synthetic traffic. This is a development test, not a production or performance claim.

The operator created a Deployment using an existing PVC containing a synthetic DNS PCAP. Suricata 8.0.8 processed the capture and emitted the expected alert, signature 9000001. The same operator created a host-network live-capture DaemonSet using NET_RAW and NET_ADMIN, without privileged mode; synthetic UDP traffic generated alert 9000002. An optional metrics Service was created with a stub exporter, so actual exporter output was not established.

For file extraction, the operator mounted an existing writable PVC into a Deployment. With Suricata file-store configuration and an extraction rule supplied for a synthetic HTTP capture, the pod wrote a file whose SHA-256 matched the test fixture: `8f8d3c41a7f807fc737f381f145a6a825ad69e96a5719b1d23ae5814b23f679f`. The operator does not itself enable file-store or create the PVC.

The configuration-backup utility also exported and restored a test sensor using the disposable cluster. That operation covers sensor spec and referenced ConfigMaps, not PVC contents or Secrets.

This exercise does not establish inline IPS/eBPF packet-drop enforcement, production traffic capture, automatic rule reload, distributed operation, actual metrics exporter output, or performance. Synthetic test artifacts and logs were retained locally under `/tmp/yas-live`; no production capture is included in this repository.
