package controller

import (
	"context"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"testing"
)

func TestReconcilesAndUpdatesSensor(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "input.pcap"}, "rules": map[string]interface{}{"claimName": "rules", "updateSchedule": "0 * * * *"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Spec.Containers[0].Image != "suricata:test" || len(d.Spec.Template.Spec.Volumes) != 2 {
		t.Fatal("missing image or capture/rules volumes")
	}
	job := &batchv1.CronJob{}
	if err := c.Get(ctx, types.NamespacedName{Name: "sensor-rules", Namespace: "default"}, job); err != nil {
		t.Fatal(err)
	}
	if job.Spec.Schedule != "0 * * * *" {
		t.Fatal("wrong schedule")
	}
	// A repeat reconcile must not create an endless Deployment update loop.
	version := d.ResourceVersion
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.ResourceVersion != version {
		t.Fatal("unchanged Deployment updated")
	}
	current := NewSensor()
	if err := c.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(current.Object, int64(0), "spec", "replicas")
	unstructured.RemoveNestedField(current.Object, "spec", "rules")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if *d.Spec.Replicas != 0 || len(d.Spec.Template.Spec.Volumes) != 1 {
		t.Fatal("scale down or rules detach failed")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "sensor-rules", Namespace: "default"}, job); !apierrors.IsNotFound(err) {
		t.Fatalf("cronjob not removed: %v", err)
	}
}
func TestRejectsCapturePathTraversal(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "../escape"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	_, err := (&Reconciler{Client: c, Scheme: scheme}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}})
	if err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestExternalConfigChangesRollEngine(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "input.pcap"}, "configRef": map[string]interface{}{"name": "sensor-config", "key": "suricata.yaml"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "sensor-config", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "first"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	engine := d.Spec.Template.Spec.Containers[0]
	found := false
	for _, a := range engine.Args {
		if a == "/etc/suricata/operator/suricata.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing config argument: %#v", engine.Args)
	}
	old := d.Spec.Template.Annotations["suricata.yas.ohbmo.com/config-sha256"]
	if old == "" {
		t.Fatal("missing config digest")
	}
	if err := c.Get(ctx, types.NamespacedName{Name: "sensor-config", Namespace: "default"}, cm); err != nil {
		t.Fatal(err)
	}
	cm.Data["suricata.yaml"] = "second"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/config-sha256"] == old {
		t.Fatal("config change did not alter pod template")
	}
}

func TestConfigMapWatchTargetsOnlyReferencingSensors(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	mk := func(name, namespace, config string) *unstructured.Unstructured {
		s := NewSensor()
		s.SetName(name)
		s.SetNamespace(namespace)
		s.Object["spec"] = map[string]interface{}{"configRef": map[string]interface{}{"name": config, "key": "x"}}
		return s
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mk("match", "n1", "shared"), mk("other", "n1", "different"), mk("cross", "n2", "shared")).Build()
	r := Reconciler{Client: c, Scheme: scheme}
	got := r.sensorsForConfigMap(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "n1"}})
	if len(got) != 1 || got[0].Name != "match" || got[0].Namespace != "n1" {
		t.Fatalf("unexpected requests: %#v", got)
	}
}

func TestMissingExternalConfigDoesNotCreateWorkload(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "input"}, "configRef": map[string]interface{}{"name": "missing", "key": "config"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := (&Reconciler{Client: c, Scheme: scheme}).Reconcile(ctx, req); err == nil {
		t.Fatal("missing config was accepted")
	}
	if err := c.Get(ctx, req.NamespacedName, &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("unexpected workload: %v", err)
	}
}

func TestExternalRulesFileChangesRollEngine(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "input.pcap"}, "rulesFileRef": map[string]interface{}{"name": "sensor-rules", "key": "rules.txt"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "sensor-rules", Namespace: "default"}, Data: map[string]string{"rules.txt": "alert tcp any any -> any any (sid:1;)"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	args := d.Spec.Template.Spec.Containers[0].Args
	found := false
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-s" && args[i+1] == "/etc/suricata/operator-rules/rules.rules" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing additive rules argument: %#v", args)
	}
	old := d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"]
	if old == "" {
		t.Fatal("missing rules digest")
	}
	cm.Data["rules.txt"] = "alert udp any any -> any any (sid:2;)"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] == old {
		t.Fatal("changed rules did not alter pod template")
	}
	got := r.sensorsForConfigMap(ctx, cm)
	if len(got) != 1 || got[0].Name != "sensor" {
		t.Fatalf("rules watch not mapped: %#v", got)
	}
}

func TestRemovingConfigAndRulesReferencesDetachesVolumes(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "image", "capture": map[string]interface{}{"claimName": "pcap", "file": "input"}, "configRef": map[string]interface{}{"name": "cm", "key": "config"}, "rulesFileRef": map[string]interface{}{"name": "cm", "key": "rules"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cm", Namespace: "default"}, Data: map[string]string{"config": "x", "rules": "y"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	current := NewSensor()
	if err := c.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	unstructured.RemoveNestedField(current.Object, "spec", "configRef")
	unstructured.RemoveNestedField(current.Object, "spec", "rulesFileRef")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if len(d.Spec.Template.Spec.Volumes) != 1 {
		t.Fatalf("old volumes remain: %#v", d.Spec.Template.Spec.Volumes)
	}
	for _, a := range d.Spec.Template.Spec.Containers[0].Args {
		if a == "-c" || a == "-s" {
			t.Fatalf("old argument remains: %s", a)
		}
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/config-sha256"] != "" || d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] != "" {
		t.Fatal("old hashes remain")
	}
}

func TestLiveCaptureDaemonSetAndModeTransition(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"interface": "eth0", "hostNetwork": true}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, req.NamespacedName, ds); err != nil {
		t.Fatal(err)
	}
	pod := ds.Spec.Template.Spec
	if !pod.HostNetwork || len(pod.Containers[0].Args) != 2 || pod.Containers[0].Args[0] != "-i" || pod.Containers[0].Args[1] != "eth0" {
		t.Fatalf("wrong live capture pod: %#v", pod)
	}
	if pod.NodeSelector["kubernetes.io/os"] != "linux" || pod.DNSPolicy != corev1.DNSClusterFirstWithHostNet || pod.Containers[0].SecurityContext == nil {
		t.Fatal("missing Linux, DNS or capture capability configuration")
	}
	if pod.Containers[0].SecurityContext.Privileged != nil && *pod.Containers[0].SecurityContext.Privileged {
		t.Fatal("unexpected privileged container")
	}

	current := NewSensor()
	if err := c.Get(ctx, req.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	_ = unstructured.SetNestedField(current.Object, map[string]interface{}{"claimName": "pcap", "file": "in.pcap"}, "spec", "capture")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, &appsv1.DaemonSet{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old DaemonSet not removed: %v", err)
	}
	if err := c.Get(ctx, req.NamespacedName, &appsv1.Deployment{}); err != nil {
		t.Fatal(err)
	}
}

func TestMultipleRuleSourcesTriggerRollout(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "rulesFileRefs": []interface{}{map[string]interface{}{"name": "one", "key": "a"}, map[string]interface{}{"name": "two", "key": "b"}}}
	one := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "one", Namespace: "default"}, Data: map[string]string{"a": "alert a"}}
	two := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "two", Namespace: "default"}, Data: map[string]string{"b": "alert b"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, one, two).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	old := d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"]
	if old == "" {
		t.Fatal("missing digest")
	}
	args := d.Spec.Template.Spec.Containers[0].Args
	found := false
	for _, a := range args {
		if a == "/etc/suricata/operator-rules/*.rules" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing glob: %v", args)
	}
	if len(r.sensorsForConfigMap(ctx, two)) != 1 {
		t.Fatal("second source not watched")
	}
	two.Data["b"] = "changed"
	if err := c.Update(ctx, two); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] == old {
		t.Fatal("second source update did not roll workload")
	}
}

func TestSensorAppliesResourceRequirements(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "resources": map[string]interface{}{"requests": map[string]interface{}{"cpu": "250m", "memory": "256Mi"}, "limits": map[string]interface{}{"cpu": "1", "memory": "1Gi"}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if got := d.Spec.Template.Spec.Containers[0].Resources.Requests.Cpu().String(); got != "250m" {
		t.Fatalf("CPU request = %s", got)
	}
}

func TestLiveCaptureCanBeDisabled(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"interface": "eth0"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	current := NewSensor()
	_ = c.Get(ctx, req.NamespacedName, current)
	_ = unstructured.SetNestedField(current.Object, int64(0), "spec", "replicas")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, req.NamespacedName, &appsv1.DaemonSet{}); !apierrors.IsNotFound(err) {
		t.Fatalf("daemonset not removed: %v", err)
	}
}

func TestSecretRuleSourceRollout(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "rulesFileRefs": []interface{}{map[string]interface{}{"kind": "Secret", "name": "restricted-rules", "key": "a"}}}
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "restricted-rules", Namespace: "default"}, Data: map[string][]byte{"a": []byte("content-one")}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, sec).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	old := d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"]
	if old == "" || len(r.sensorsForConfigMap(ctx, sec)) != 1 {
		t.Fatal("secret reference not hashed or watched")
	}
	found := false
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Projected != nil && len(v.Projected.Sources) > 0 && v.Projected.Sources[0].Secret != nil {
			found = true
		}
	}
	if !found {
		t.Fatal("secret not projected")
	}
	sec.Data["a"] = []byte("content-two")
	if err := c.Update(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, req.NamespacedName, d)
	if d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] == old {
		t.Fatal("secret change did not alter workload")
	}
}

func TestMetricsServiceAndMonitorLifecycle(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	scheme.AddKnownTypeWithName(SensorGVK.GroupVersion().WithKind("SuricataSensorList"), &unstructured.UnstructuredList{})
	monitorGVK := schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}
	scheme.AddKnownTypeWithName(monitorGVK, &unstructured.Unstructured{})
	scheme.AddKnownTypeWithName(monitorGVK.GroupVersion().WithKind("ServiceMonitorList"), &unstructured.UnstructuredList{})
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "metrics": map[string]interface{}{"exporterImage": "exporter:v1", "port": int64(9100), "serviceMonitor": true}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	if len(d.Spec.Template.Spec.Containers) != 2 || d.Spec.Template.Spec.Containers[1].Image != "exporter:v1" {
		t.Fatal("missing metrics sidecar")
	}
	key := types.NamespacedName{Name: "sensor-metrics", Namespace: "default"}
	svc := &corev1.Service{}
	if err := c.Get(ctx, key, svc); err != nil {
		t.Fatal(err)
	}
	if len(svc.Spec.Ports) != 1 || svc.Spec.Ports[0].Port != 9100 {
		t.Fatal("wrong service port")
	}
	sm := &unstructured.Unstructured{}
	sm.SetGroupVersionKind(monitorGVK)
	if err := c.Get(ctx, key, sm); err != nil {
		t.Fatal(err)
	}
	current := NewSensor()
	_ = c.Get(ctx, req.NamespacedName, current)
	unstructured.RemoveNestedField(current.Object, "spec", "metrics")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, key, svc); !apierrors.IsNotFound(err) {
		t.Fatal("metrics service retained")
	}
	if err := c.Get(ctx, key, sm); !apierrors.IsNotFound(err) {
		t.Fatal("monitor retained")
	}
	_ = c.Get(ctx, req.NamespacedName, d)
	if len(d.Spec.Template.Spec.Containers) != 1 {
		t.Fatal("metrics sidecar retained")
	}
}

func TestFileExtractionMountLifecycle(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "fileExtraction": map[string]interface{}{"claimName": "files", "mountPath": "/var/log/suricata/filestore"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	d := &appsv1.Deployment{}
	if err := c.Get(ctx, req.NamespacedName, d); err != nil {
		t.Fatal(err)
	}
	var foundMount, foundVolume bool
	for _, m := range d.Spec.Template.Spec.Containers[0].VolumeMounts {
		if m.Name == "filestore" && m.MountPath == "/var/log/suricata/filestore" && !m.ReadOnly {
			foundMount = true
		}
	}
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == "filestore" && v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "files" {
			foundVolume = true
		}
	}
	if !foundMount || !foundVolume {
		t.Fatal("file store PVC not mounted")
	}
	current := NewSensor()
	_ = c.Get(ctx, req.NamespacedName, current)
	unstructured.RemoveNestedField(current.Object, "spec", "fileExtraction")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(ctx, req.NamespacedName, d)
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == "filestore" {
			t.Fatal("removed file store still mounted")
		}
	}
}
func TestFileExtractionRejectsUnsafeMountPath(t *testing.T) {
	for _, p := range []string{"/", "relative", "/capture", "/capture/inside", "/etc/suricata/operator/subdir", "/a/../b"} {
		t.Run(p, func(t *testing.T) {
			ctx := context.Background()
			scheme := runtime.NewScheme()
			_ = appsv1.AddToScheme(scheme)
			_ = corev1.AddToScheme(scheme)
			scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
			s := NewSensor()
			s.SetName("sensor")
			s.SetNamespace("default")
			s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"claimName": "c", "file": "in"}, "fileExtraction": map[string]interface{}{"claimName": "files", "mountPath": p}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
			_, err := (&Reconciler{Client: c, Scheme: scheme}).Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}})
			if err == nil {
				t.Fatal("unsafe mount path accepted")
			}
		})
	}
}

func TestInlineAFPacketRequiresSymmetricConfig(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"inlineInterfaces": []interface{}{"eth1", "eth2"}, "hostNetwork": true}, "configRef": map[string]interface{}{"name": "cfg", "key": "suricata.yaml"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "af-packet:\n  - interface: eth1\n    copy-mode: ips\n    copy-iface: eth2\n  - interface: eth2\n    copy-mode: ips\n    copy-iface: eth1\n"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, req.NamespacedName, ds); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range ds.Spec.Template.Spec.Containers[0].Args {
		if a == "--af-packet" {
			found = true
		}
	}
	if !found {
		t.Fatal("inline capture mode missing")
	}
	cm.Data["suricata.yaml"] = "af-packet:\n  - interface: eth1\n    copy-mode: tap\n    copy-iface: eth2\n"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err == nil {
		t.Fatal("asymmetric non-IPS config accepted")
	}
}

func TestInlineCanBeDisabledWithBrokenConfig(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"inlineInterfaces": []interface{}{"eth1", "eth2"}, "hostNetwork": true}, "configRef": map[string]interface{}{"name": "cfg", "key": "suricata.yaml"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "default-log-dir: /var/log/suricata\noutputs:\n - eve-log:\n     enabled: true\n     filetype: regular\n     filename: eve.json\naf-packet:\n - interface: eth1\n   copy-mode: ips\n   copy-iface: eth2\n - interface: eth2\n   copy-mode: ips\n   copy-iface: eth1\n"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, cm); err != nil {
		t.Fatal(err)
	}
	current := NewSensor()
	_ = c.Get(ctx, req.NamespacedName, current)
	_ = unstructured.SetNestedField(current.Object, int64(0), "spec", "replicas")
	if err := c.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("cannot disable inline with missing config: %v", err)
	}
	if err := c.Get(ctx, req.NamespacedName, &appsv1.DaemonSet{}); !apierrors.IsNotFound(err) {
		t.Fatal("inline daemonset was not removed")
	}
}

func TestXDPVerdictSidecarWiring(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = batchv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	scheme.AddKnownTypeWithName(SensorGVK, NewSensor())
	s := NewSensor()
	s.SetName("sensor")
	s.SetNamespace("default")
	s.SetUID(types.UID("uid"))
	s.Object["spec"] = map[string]interface{}{"image": "i", "capture": map[string]interface{}{"inlineInterfaces": []interface{}{"eth1", "eth2"}, "hostNetwork": true, "xdpVerdictCache": map[string]interface{}{"image": "xdp:test", "ttlSeconds": int64(30)}}, "configRef": map[string]interface{}{"name": "cfg", "key": "suricata.yaml"}}
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cfg", Namespace: "default"}, Data: map[string]string{"suricata.yaml": "default-log-dir: /var/log/suricata\noutputs:\n - eve-log:\n     enabled: true\n     filetype: regular\n     filename: eve.json\naf-packet:\n - interface: eth1\n   copy-mode: ips\n   copy-iface: eth2\n - interface: eth2\n   copy-mode: ips\n   copy-iface: eth1\n"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, cm).Build()
	r := &Reconciler{Client: c, Scheme: scheme}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: "sensor", Namespace: "default"}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatal(err)
	}
	ds := &appsv1.DaemonSet{}
	if err := c.Get(ctx, req.NamespacedName, ds); err != nil {
		t.Fatal(err)
	}
	pod := ds.Spec.Template.Spec
	if len(pod.Containers) != 2 || pod.Containers[1].Name != "xdp-verdict" {
		t.Fatal("missing verdict sidecar")
	}
	if pod.Containers[1].SecurityContext == nil || pod.Containers[1].SecurityContext.SeccompProfile == nil {
		t.Fatal("missing BPF security context")
	}
	if len(pod.Containers[1].Args) == 0 || pod.Containers[1].Args[1] != "eth1" {
		t.Fatal("wrong ingress interface")
	}
	shared := 0
	for _, v := range pod.Volumes {
		if v.Name == "eve-log" && v.EmptyDir != nil {
			shared++
		}
	}
	if shared != 1 {
		t.Fatal("missing shared eve log")
	}
}
