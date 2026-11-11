package backup

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestExportRestoreSensorAndReferencedConfig(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	sensor := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "suricata.yas.ohbmo.com/v1alpha1", "kind": "SuricataSensor", "metadata": map[string]interface{}{"name": "probe", "namespace": "default"}, "spec": map[string]interface{}{"image": "suricata:v1", "configRef": map[string]interface{}{"name": "sensor-config", "key": "config.yaml"}}}}
	sensor.SetGroupVersionKind(schema.GroupVersionKind{Group: "suricata.yas.ohbmo.com", Version: "v1alpha1", Kind: "SuricataSensor"})
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "sensor-config", Namespace: "default"}, Data: map[string]string{"config.yaml": "enabled: true"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sensor, cm).Build()
	snapshot, err := Capture(ctx, c, types.NamespacedName{Namespace: "default", Name: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, sensor); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, cm); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, c, snapshot); err != nil {
		t.Fatal(err)
	}
	got := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: "sensor-config", Namespace: "default"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Data["config.yaml"] != "enabled: true" {
		t.Fatalf("wrong restored config %v", got.Data)
	}
	restored := &unstructured.Unstructured{}
	restored.SetGroupVersionKind(sensor.GroupVersionKind())
	if err := c.Get(ctx, types.NamespacedName{Name: "probe", Namespace: "default"}, restored); err != nil {
		t.Fatal(err)
	}
	if value, _, _ := unstructured.NestedString(restored.Object, "spec", "image"); value != "suricata:v1" {
		t.Fatalf("wrong restored image %q", value)
	}
}
func TestCaptureFailsWhenReferenceMissing(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	s := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "suricata.yas.ohbmo.com/v1alpha1", "kind": "SuricataSensor", "metadata": map[string]interface{}{"name": "probe", "namespace": "default"}, "spec": map[string]interface{}{"configRef": map[string]interface{}{"name": "missing", "key": "config.yaml"}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	if _, err := Capture(ctx, c, types.NamespacedName{Name: "probe", Namespace: "default"}); err == nil {
		t.Fatal("expected missing reference error")
	}
}

func TestMultipleRuleSourcesRoundTripAndRejectIncompleteBackup(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	s := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "suricata.yas.ohbmo.com/v1alpha1", "kind": "SuricataSensor", "metadata": map[string]interface{}{"name": "probe", "namespace": "default"}, "spec": map[string]interface{}{"rulesFileRefs": []interface{}{map[string]interface{}{"name": "rules-a", "key": "a.rules"}, map[string]interface{}{"name": "rules-b", "key": "b.rules"}}}}}
	a := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "rules-a", Namespace: "default"}, Data: map[string]string{"a.rules": "rule a"}}
	b := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "rules-b", Namespace: "default"}, Data: map[string]string{"b.rules": "rule b"}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s, a, b).Build()
	snapshot, err := Capture(ctx, c, types.NamespacedName{Name: "probe", Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ConfigMaps) != 2 {
		t.Fatalf("expected two maps, got %d", len(snapshot.ConfigMaps))
	}
	snapshot.ConfigMaps = snapshot.ConfigMaps[:1]
	if err := Restore(ctx, c, snapshot); err == nil {
		t.Fatal("incomplete backup must be rejected before writes")
	}
}

func TestSecretRuleReferenceIsNotIncludedInSnapshot(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	s := &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": "suricata.yas.ohbmo.com/v1alpha1", "kind": "SuricataSensor", "metadata": map[string]interface{}{"name": "probe", "namespace": "default"}, "spec": map[string]interface{}{"rulesFileRefs": []interface{}{map[string]interface{}{"kind": "Secret", "name": "private-rules", "key": "rules"}}}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(s).Build()
	snapshot, err := Capture(ctx, c, types.NamespacedName{Name: "probe", Namespace: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.ConfigMaps) != 0 {
		t.Fatal("Secret was included as ConfigMap")
	}
	if err := Restore(ctx, c, snapshot); err != nil {
		t.Fatal(err)
	}
}
