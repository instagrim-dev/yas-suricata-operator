# Recovered dynamic XDP verdict path: assessment

This records an investigation of the earlier p6m Suricata operator at commit `fc517c9869e937962693d9639b73228fac8f15c8`. The historical path was not directly portable. The operator now has a separate, narrowly scoped optional verdict cache described in the README; the points below explain why the recovered wiring was not copied unchanged.

## What exists

The recovered `pkg/suricata/ips/ebpf/runtime.go` has a real `link.AttachXDP` call, used by the recovered XDP fast-path manager. A separate `CiliumEBPFLibrary.AttachProgram` is a placeholder. A real attachment function therefore exists, but the following end-to-end verdict path is not established.

A capability probe in a disposable, network-isolated Linux container succeeded in `BPF_MAP_CREATE` with `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, and an unconfined seccomp profile. This demonstrates that the test kernel can create a BPF map under that configuration; it does not demonstrate XDP attachment, a Kubernetes deployment, or dynamic packet enforcement.

## Decisive gaps

1. The recovered EVE listener (`pkg/suricata/ips/ebpf/suricata_integration.go`) has no caller in the recovered reconciler. It assumes that Suricata's command socket supports an alert subscription, which this investigation has not established.
2. The recovered listener tests `alert.action` for `drop` or `reject` and reads the flow tuple under `alert.flow`. The Suricata 8.0.8 inline experiment actually emitted `alert.action: blocked` with `src_ip`, `dest_ip`, ports, and protocol at the event's top level. The recovered listener would not turn this observed event into a drop-map entry. [Suricata's EVE format documentation](https://docs.suricata.io/en/suricata-8.0.6/output/eve/eve-json-format.html) also describes the top-level tuple and distinguishes alert action and packet verdict.
3. The recovered fast-path loader uses `ebpf.NewCollection(spec)`, while its integration routine only checks/logs the separate drop map. It does not demonstrate that the XDP program refers to the map updated by the verdict consumer. A working implementation needs an explicit verified shared-map binding and lifecycle.
4. The recovered userspace drop insertion uses `time.Now().UnixNano()`, while the XDP program compares its value against `bpf_ktime_get_ns()`. Those are different clock domains; expiration arithmetic cannot be relied on as written.
5. The project needs a node-local event consumer and attach/detach lifecycle with explicit interface scope, restart behavior, privilege and failure semantics, plus tests showing the *first* Suricata verdict and the effect on a subsequent matching packet. Runtime compilation and private platform dependencies in the recovered project also need to be resolved.

These are integration and correctness gaps, not a conclusion that the feature is impossible. The previously verified AF_PACKET inline mode remains independent of this assessment and is not eBPF/XDP enforcement.

## Current narrow integration

The opt-in sidecar consumes new Suricata EVE events, decodes top-level blocked IPv4 TCP/UDP tuples, inserts them into the same map used by its attached XDP program, and uses monotonic bounded expiry. It attaches only to the first inline interface and fails open back to Suricata for uncached, unsupported or expired flows. See the README and live-verification record for full scope, failure semantics and the controlled UDP test; do not interpret this as completing the historical fast-path architecture.
