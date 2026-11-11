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
