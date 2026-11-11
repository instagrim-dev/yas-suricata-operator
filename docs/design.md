# Design

A `SuricataSensor` is namespaced and owns one Deployment and, if configured, one rule-update CronJob. Capture and rules volumes exist independently of the sensor and outlive it. The operator reads desired configuration and reconciles resources with Kubernetes controller references; running engines are not assumed healthy just because their resources exist.

The API is intentionally separate from the historical YAS KSensor API. This project was newly authored based on the YAS objective of reconciling a Suricata engine and periodic rule updater. It does not include YAS's prior vendor-specific source, configuration or Git history.
