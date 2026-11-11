package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"
)

func TestAPIServerCreateUpdateAndDisable(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to Kubernetes envtest binaries")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextv1.CustomResourceDefinition{}
	if err = json.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	env := &envtest.Environment{CRDs: []*apiextv1.CustomResourceDefinition{crd}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := NewSensor()
	s.SetName("example")
	s.SetNamespace("default")
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "engine-settings", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "version-one", "custom.rules": "alert tcp any any -> any any (sid:1;)"}}
	if err = c.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "incoming"}, "rules": map[string]interface{}{"claimName": "rules", "updateSchedule": "0 * * * *"}}
	s.Object["spec"].(map[string]interface{})["configRef"] = map[string]interface{}{"name": "engine-settings", "key": "suricata.yaml"}
	s.Object["spec"].(map[string]interface{})["rulesFileRef"] = map[string]interface{}{"name": "engine-settings", "key": "custom.rules"}
	if err = c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "example", Namespace: "default"}}
	r := &Reconciler{Client: c, Scheme: scheme}
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err = c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/config-sha256"] == "" || d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] == "" {
		t.Fatal("API server lost config or rule references")
	}
	oldRules := d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"]
	if err = c.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatal(err)
	}
	cm.Data["custom.rules"] = "alert udp any any -> any any (sid:2;)"
	if err = c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] == oldRules {
		t.Fatal("changed rules not reflected on pod template")
	}
	version := d.ResourceVersion
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.ResourceVersion != version {
		t.Fatal("unchanged deployment caused another write")
	}
	job := &batchv1.CronJob{}
	if err = c.Get(ctx, types.NamespacedName{Name: "example-rules", Namespace: "default"}, job); err != nil {
		t.Fatal(err)
	}
	if !metav1.IsControlledBy(job, s) {
		t.Fatal("cronjob missing owner")
	}
	current := NewSensor()
	if err = c.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(current.Object, "suricata:updated", "spec", "image")
	_ = unstructured.SetNestedField(current.Object, int64(0), "spec", "replicas")
	if err = c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Spec.Containers[0].Image != "suricata:updated" || *d.Spec.Replicas != 0 {
		t.Fatal("image update or scale down failed")
	}
	if err = c.Get(ctx, types.NamespacedName{Name: "example-rules", Namespace: "default"}, job); err != nil {
		t.Fatal(err)
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		t.Fatal("rules schedule not suspended")
	}
	if err = c.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	unstructured.RemoveNestedField(current.Object, "spec", "rules")
	if err = c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, types.NamespacedName{Name: "example-rules", Namespace: "default"}, job); !apierrors.IsNotFound(err) {
		t.Fatalf("rules job still exists: %v", err)
	}

	live := NewSensor()
	live.SetName("live")
	live.SetNamespace("default")
	live.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"interface": "eth0", "hostNetwork": true, "nodeSelector": map[string]interface{}{"pool": "sensor"}}, "fileExtraction": map[string]interface{}{"claimName": "files", "mountPath": "/var/log/suricata/filestore"}}
	if err = c.Create(ctx, live); err != nil {
		t.Fatal(err)
	}
	liveReq := ctrl.Request{NamespacedName: types.NamespacedName{Name: "live", Namespace: "default"}}
	if _, err = r.Reconcile(ctx, liveReq); err != nil {
		t.Fatal(err)
	}
	ds := &appsv1.DaemonSet{}
	if err = c.Get(ctx, liveReq.NamespacedName, ds); err != nil {
		t.Fatal(err)
	}
	if !ds.Spec.Template.Spec.HostNetwork || ds.Spec.Template.Spec.NodeSelector["pool"] != "sensor" || ds.Spec.Template.Spec.NodeSelector["kubernetes.io/os"] != "linux" {
		t.Fatal("API server rejected or lost live capture settings")
	}
	fileVolume := false
	for _, v := range ds.Spec.Template.Spec.Volumes {
		if v.Name == "filestore" && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "files" {
			fileVolume = true
		}
	}
	if !fileVolume {
		t.Fatal("API server rejected or lost file extraction PVC")
	}

	inlineCM := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "inline-config", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "default-log-dir: /var/log/suricata\noutputs:\n  - eve-log:\n      enabled: true\n      filetype: regular\n      filename: eve.json\naf-packet:\n  - interface: ingress0\n    copy-mode: ips\n    copy-iface: egress0\n  - interface: egress0\n    copy-mode: ips\n    copy-iface: ingress0\n"}}
	if err = c.Create(ctx, inlineCM); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, liveReq.NamespacedName, live); err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(live.Object, map[string]interface{}{"inlineInterfaces": []interface{}{"ingress0", "egress0"}, "hostNetwork": true, "xdpVerdictCache": map[string]interface{}{"image": "xdp:test", "ttlSeconds": int64(3)}}, "spec", "capture")
	_ = unstructured.SetNestedField(live.Object, map[string]interface{}{"name": "inline-config", "key": "suricata.yaml"}, "spec", "configRef")
	if err = c.Update(ctx, live); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Reconcile(ctx, liveReq); err != nil {
		t.Fatal(err)
	}
	if err = c.Get(ctx, liveReq.NamespacedName, ds); err != nil {
		t.Fatal(err)
	}
	if len(ds.Spec.Template.Spec.Containers[0].Args) < 1 || ds.Spec.Template.Spec.Containers[0].Args[0] != "--af-packet" {
		t.Fatal("inline mode not persisted")
	}
	if len(ds.Spec.Template.Spec.Containers) != 2 || ds.Spec.Template.Spec.Containers[1].Name != "xdp-verdict" {
		t.Fatal("XDP verdict sidecar not persisted")
	}

}

// This exercises the real manager's ConfigMap watch, rather than calling Reconcile directly.
func TestManagerReactsToRulesConfigMapUpdate(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to Kubernetes envtest binaries")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	crd := &apiextv1.CustomResourceDefinition{}
	if err = json.Unmarshal(data, crd); err != nil {
		t.Fatal(err)
	}
	env := &envtest.Environment{CRDs: []*apiextv1.CustomResourceDefinition{crd}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if err = (&Reconciler{Client: mgr.GetClient(), Scheme: scheme}).Setup(mgr); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: "default"}, Data: map[string]string{"custom.rules": "one"}}
	if err = c.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "incoming"}, "rulesFileRef": map[string]interface{}{"name": "rules", "key": "custom.rules"}}
	if err = c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	key := types.NamespacedName{Name: "sensor", Namespace: "default"}
	var initial string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d := &appsv1.Deployment{}
		if c.Get(ctx, key, d) == nil && d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] != "" {
			initial = d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"]
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if initial == "" {
		t.Fatal("manager did not create deployment")
	}
	if err = c.Get(ctx, client.ObjectKeyFromObject(cm), cm); err != nil {
		t.Fatal(err)
	}
	cm.Data["custom.rules"] = "two"
	if err = c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		d := &appsv1.Deployment{}
		if c.Get(ctx, key, d) == nil && d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] != "" && d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] != initial {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("manager did not roll deployment after rules ConfigMap update")
}

func TestAPIServerMetricsServiceMonitor(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS to Kubernetes envtest binaries")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "crd.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := yaml.YAMLToJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	sensorCRD := &apiextv1.CustomResourceDefinition{}
	if err = json.Unmarshal(data, sensorCRD); err != nil {
		t.Fatal(err)
	}
	preserve := true
	monitorCRD := &apiextv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: "servicemonitors.monitoring.coreos.com"}, Spec: apiextv1.CustomResourceDefinitionSpec{Group: "monitoring.coreos.com", Scope: apiextv1.NamespaceScoped, Names: apiextv1.CustomResourceDefinitionNames{Plural: "servicemonitors", Singular: "servicemonitor", Kind: "ServiceMonitor"}, Versions: []apiextv1.CustomResourceDefinitionVersion{{Name: "v1", Served: true, Storage: true, Schema: &apiextv1.CustomResourceValidation{OpenAPIV3Schema: &apiextv1.JSONSchemaProps{Type: "object", XPreserveUnknownFields: &preserve}}}}}}
	env := &envtest.Environment{CRDs: []*apiextv1.CustomResourceDefinition{sensorCRD, monitorCRD}}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := NewSensor()
	s.SetName("monitored")
	s.SetNamespace("default")
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "incoming"}, "metrics": map[string]interface{}{"exporterImage": "exporter:test", "port": int64(9100), "serviceMonitor": true}}
	if err = c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "monitored", Namespace: "default"}}
	r := &Reconciler{Client: c, Scheme: scheme}
	if _, err = r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	key := types.NamespacedName{Name: "monitored-metrics", Namespace: "default"}
	svc := &corev1.Service{}
	if err = c.Get(ctx, key, svc); err != nil {
		t.Fatal(err)
	}
	if svc.Spec.Ports[0].Port != 9100 {
		t.Fatal("port not persisted")
	}
	sm := &unstructured.Unstructured{}
	sm.SetGroupVersionKind(schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"})
	if err = c.Get(ctx, key, sm); err != nil {
		t.Fatal(err)
	}
}
