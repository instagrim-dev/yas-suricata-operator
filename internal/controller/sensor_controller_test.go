package controller

import (
	"context"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
