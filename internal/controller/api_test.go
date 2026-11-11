package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
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
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := NewSensor()
	s.SetName("example")
	s.SetNamespace("default")
	s.Object["spec"] = map[string]interface{}{"image": "suricata:test", "capture": map[string]interface{}{"claimName": "pcap", "file": "incoming"}, "rules": map[string]interface{}{"claimName": "rules", "updateSchedule": "0 * * * *"}}
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

}
