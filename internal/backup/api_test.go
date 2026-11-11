package backup

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

func TestAPIServerSnapshotRestore(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
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
	config, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	}()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: "default"}, Data: map[string]string{"local.rules": "alert icmp any any -> any any (sid:1000001;)"}}
	if err := c.Create(ctx, cm); err != nil {
		t.Fatal(err)
	}
	s := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "suricata.yas.ohbmo.com/v1alpha1", "kind": "SuricataSensor", "metadata": map[string]interface{}{"name": "probe", "namespace": "default"}, "spec": map[string]interface{}{"image": "suricata:v1", "capture": map[string]interface{}{"claimName": "capture", "file": "packets"}, "rulesFileRef": map[string]interface{}{"name": "rules", "key": "local.rules"}}}}
	if err := c.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	snap, err := Capture(ctx, c, types.NamespacedName{Namespace: "default", Name: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	snap = &decoded
	cm.Data["local.rules"] = "changed"
	if err := c.Update(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, c, snap); err != nil {
		t.Fatal(err)
	}
	updated := &corev1.ConfigMap{}
	if err := c.Get(ctx, client.ObjectKeyFromObject(cm), updated); err != nil {
		t.Fatal(err)
	}
	if updated.Data["local.rules"] != "alert icmp any any -> any any (sid:1000001;)" {
		t.Fatal("rules not restored")
	}
}
