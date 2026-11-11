# YAS Suricata Operator

A Kubernetes controller for Suricata packet-capture workloads, supporting offline PCAP files and live capture from network interfaces. It is a standalone project informed by YAS's Suricata orchestration; it does not require the YAS monolith, Zeek, or a Corelight deployment.

This is an early implementation. It has processed synthetic capture and live traffic in a disposable Kubernetes cluster; see the verification record for scope. No operator container image has been published for this project.

## What it does

A namespaced `SuricataSensor` creates one same-named Deployment. The operator mounts an existing capture PVC at `/capture` and runs `suricata -r /capture/<file> --pcap-file-continuous`. The path can name a PCAP file or a directory; continuously adding files to a directory is the intended streaming pattern. It does not provide packet capture or transport. See [Suricata's command-line documentation](https://docs.suricata.io/en/suricata-7.0.15/command-line-options.html).

For live capture, configure an interface instead of a capture PVC:

```yaml
spec:
  image: YOUR_SURICATA_IMAGE
  capture:
    interface: eth0
    hostNetwork: true
    nodeSelector:
      capture: enabled
```

This creates a DaemonSet on matching Linux nodes. `hostNetwork: true` lets Suricata observe the named host network interface; with `false`, it observes the pod network namespace instead. Select only intended nodes, and ensure the image and cluster security policy permit `NET_RAW` and `NET_ADMIN`. The pod is not configured as privileged. With `replicas: 1`, live mode runs one pod per selected node; `replicas: 0` removes the owned DaemonSet and suspends its optional rule updater. Switching modes removes the previous workload only if the sensor owns it. Existing packet capture PVCs are not removed.

Set `replicas: 0` to stop the engine and suspend the optional rule updater. Enabling `rules` creates a CronJob running `suricata-update` with an existing PVC mounted at `/var/lib/suricata/rules`. The running engine does **not** automatically reload updated rules; trigger a [rule reload](https://docs.suricata.io/en/suricata-7.0.14/rule-management/rule-reload.html) or restart it. Use a volume and scheduling configuration that permit the engine and updater to access the same rules store. The chosen engine image must contain `suricata`, its configuration, and, if rules updates are enabled, `suricata-update`.

You may reference a same-namespace ConfigMap for engine configuration and an optional, additional rules file:

```yaml
spec:
  configRef:
    name: my-suricata-config
    key: suricata.yaml
  rulesFileRef:
    name: my-custom-rules
    key: custom.rules
```

For several additional rules files, use `spec.rulesFileRefs`, an array of `{name, key}` references. Entries default to ConfigMaps; set `kind: Secret` to use a Secret's data key. The existing singular `rulesFileRef` can be used with this list. Sources are projected as distinct `.rules` files, selected with Suricata's documented glob support, watched and included in the rollout digest. All referenced objects must be in the sensor's namespace. The operator needs read/watch permission for Secrets to support Secret-backed rule sources.

The operator mounts the selected entries read-only, passes the config with `-c` and the additional rules with `-s`, and updates the Pod template when either entry changes. Kubernetes then replaces the Pod using the Deployment's Recreate strategy. ConfigMaps must exist and contain the selected keys; they are user-owned. The operator does not validate Suricata YAML or rule syntax. `-s` adds to rules in the engine configuration; do not duplicate signature IDs. Scheduled PVC rule updates still require a reload or restart separately.

Optional `spec.resources.requests` and `spec.resources.limits` set standard Kubernetes CPU and memory quantities for the engine container in either capture mode.

Suricata's image configuration controls where EVE output goes; this operator does not promise stdout logging. Checksum validation is left to the image configuration by default. To disable checksum checking for captures where offload makes it inappropriate, set `spec.disableChecksumValidation: true`.

## File extraction storage

Suricata file extraction is enabled through the Suricata YAML supplied via `configRef`; the operator does not enable the file-store output or select which traffic to store. To provide persistent writable storage for it, set:

```yaml
spec:
  fileExtraction:
    claimName: extracted-files
    mountPath: /var/log/suricata/filestore
```

Set Suricata's `file-store.dir` to the same mount path, enable its `file-store` output, and configure a `filestore` rule or Suricata's force-filestore option. The PVC must already exist in the sensor namespace and support the scheduling/access pattern of the Deployment or DaemonSet. The operator mounts it read/write, but never creates or deletes the claim. Omitting `fileExtraction` removes the mount; it does not erase stored files. The configuration backup covers the sensor and referenced configuration, not the PVC contents.

## Metrics integration

To expose a user-supplied Prometheus-compatible exporter as a sidecar, configure:

```yaml
spec:
  metrics:
    exporterImage: YOUR_EXPORTER_IMAGE
    port: 9100
    args: []
    path: /metrics
    serviceMonitor: true
```

The controller exposes the sidecar through a per-sensor Service. Setting `serviceMonitor: true` additionally creates a ServiceMonitor and requires the Prometheus Operator ServiceMonitor CRD. The user-provided exporter must be configured to collect and expose the desired Suricata metrics; this operator does not provide or validate an exporter. The Prometheus deployment must select the ServiceMonitor. Disabling metrics removes only the resources owned by the sensor. The same settings work with offline Deployments and live DaemonSets.

## Try it

Requirements: Go 1.21+, Docker (or another image builder), `kubectl`, a Kubernetes cluster, and a compatible Suricata image. The cluster needs an existing PVC with an `incoming` directory containing PCAP files. A producer must populate that volume; the operator does not create or populate it.

1. Build and publish (or load into your cluster) an operator image:

   ```sh
   docker build -t YOUR_REGISTRY/yas-suricata-operator:dev .
   docker push YOUR_REGISTRY/yas-suricata-operator:dev
   ```

2. Set the image in the local manifests and install:

   ```sh
   cd config
   kubectl kustomize . | sed 's@controller:latest@YOUR_REGISTRY/yas-suricata-operator:dev@' | kubectl apply -f -
   cd ..
   kubectl -n yas-suricata-system rollout status deployment/yas-suricata-operator
   ```

3. Copy `config/sample.yaml`, replace the example image and PVC names with values available to the cluster, then apply it. The PVC must be in the same namespace as the sensor.

   ```sh
   kubectl apply -f your-sensor.yaml
   kubectl -n default get suricatasensors,deployments
   kubectl -n default logs deployment/example -c suricata
   ```

The image name in `config/operator.yaml` is a local build placeholder, not a published image. Review the Suricata image's startup requirements and configuration. EVE logs may be written to a file instead of the container log; check that image's configuration.

See [live verification](docs/live-verification.md) for the bounded Kubernetes and synthetic traffic tests.

## Development and tests

```sh
go test ./...
go vet ./...
kubectl kustomize config
```

Unit tests use a fake Kubernetes client. An additional API-server test runs when `KUBEBUILDER_ASSETS` points to matching `kube-apiserver`, `etcd`, and `kubectl` binaries; otherwise that test skips. The API-server tests validate resource creation, repeated reconciliation, and a running manager reacting to ConfigMap changes and Kubernetes API acceptance of live-mode DaemonSets, not packet capture, image compatibility or traffic analysis.

## Design and limits

The controller owns its engine Deployment and optional update CronJob. It refuses to take over an object controlled by another resource. Kubernetes garbage collection removes owned resources when the sensor is deleted. Capture and rules PVCs are user-managed and are not deleted by this operator. Each sensor should have distinct PVC inputs; the sample expects one engine replica and uses the Recreate strategy.

This project uses its own `suricata.yas.ohbmo.com/v1alpha1` API. Existing YAS `KSensor` resources are **not** automatically migrated. Sensor config, logs, rule updates, transport integrations and mesh sidecars from the historical YAS project are not a drop-in compatibility contract. Review packet handling and engine configuration before use.

## License

[Apache License 2.0](LICENSE).

## Configuration backup and restore

The backup utility exports a sensor's desired spec and referenced ConfigMaps to a JSON file, and can restore them to the original namespace and names:

```sh
go run ./cmd/suricata-backup export --namespace default --name example --file ./sensor-backup.json
go run ./cmd/suricata-backup restore --file ./sensor-backup.json
```

Export writes the file with owner-only permissions. Restore replaces the sensor spec and data of referenced ConfigMaps; it is a sequence of Kubernetes writes, not an atomic transaction. PVC contents and Secrets are not included. Restore referenced Secrets and storage separately. Configuration and rules may contain sensitive information, so store the backup accordingly. The utility uses the caller's Kubernetes credentials and permissions.
