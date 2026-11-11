// Package backup snapshots a SuricataSensor and the ConfigMaps it references.
package backup

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var sensorKind = schema.GroupVersionKind{Group: "suricata.yas.ohbmo.com", Version: "v1alpha1", Kind: "SuricataSensor"}

type ConfigMap struct {
	Name       string            `json:"name"`
	Data       map[string]string `json:"data,omitempty"`
	BinaryData map[string][]byte `json:"binaryData,omitempty"`
}
type Snapshot struct {
	Version    int                    `json:"version"`
	Name       string                 `json:"name"`
	Namespace  string                 `json:"namespace"`
	Spec       map[string]interface{} `json:"spec"`
	ConfigMaps []ConfigMap            `json:"configMaps"`
}

// Capture snapshots desired sensor state and all referenced ConfigMaps. PVC contents and Secrets are excluded.
func Capture(ctx context.Context, c client.Client, key types.NamespacedName) (*Snapshot, error) {
	sensor := &unstructured.Unstructured{}
	sensor.SetGroupVersionKind(sensorKind)
	if err := c.Get(ctx, key, sensor); err != nil {
		return nil, fmt.Errorf("read sensor: %w", err)
	}
	spec, ok, err := unstructured.NestedMap(sensor.Object, "spec")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("sensor has no spec")
	}
	refs, err := references(spec)
	if err != nil {
		return nil, err
	}
	result := &Snapshot{Version: 1, Name: key.Name, Namespace: key.Namespace, Spec: spec, ConfigMaps: []ConfigMap{}}
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cm := &corev1.ConfigMap{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: name}, cm); err != nil {
			return nil, fmt.Errorf("read referenced ConfigMap %s: %w", name, err)
		}
		for _, k := range refs[name] {
			if _, found := cm.Data[k]; !found {
				return nil, fmt.Errorf("ConfigMap %s missing data key %s", name, k)
			}
		}
		result.ConfigMaps = append(result.ConfigMaps, ConfigMap{Name: name, Data: cm.DeepCopy().Data, BinaryData: cm.DeepCopy().BinaryData})
	}
	return result, nil
}

func references(spec map[string]interface{}) (map[string][]string, error) {
	refs := map[string][]string{}
	add := func(value interface{}) error {
		m, ok := value.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid ConfigMap reference")
		}
		name, _ := m["name"].(string)
		key, _ := m["key"].(string)
		if name == "" || key == "" {
			return fmt.Errorf("reference requires name and key")
		}
		kind, _ := m["kind"].(string)
		if kind == "Secret" {
			return nil
		}
		if kind != "" && kind != "ConfigMap" {
			return fmt.Errorf("unsupported reference kind %q", kind)
		}
		refs[name] = append(refs[name], key)
		return nil
	}
	for _, field := range []string{"configRef", "rulesFileRef"} {
		if v, ok := spec[field]; ok && v != nil {
			if err := add(v); err != nil {
				return nil, fmt.Errorf("%s: %w", field, err)
			}
		}
	}
	if v, ok := spec["rulesFileRefs"]; ok && v != nil {
		items, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid rulesFileRefs")
		}
		for _, item := range items {
			if err := add(item); err != nil {
				return nil, fmt.Errorf("rulesFileRefs: %w", err)
			}
		}
	}
	return refs, nil
}

// Restore applies captured ConfigMap content and then sensor spec to the original namespace/name.
// Existing referenced ConfigMaps and the sensor spec are overwritten; PVC contents are not restored.
func Restore(ctx context.Context, c client.Client, s *Snapshot) error {
	if s == nil || s.Version != 1 || s.Name == "" || s.Namespace == "" || s.Spec == nil {
		return fmt.Errorf("invalid backup")
	}
	refs, err := references(s.Spec)
	if err != nil {
		return err
	}
	maps := map[string]ConfigMap{}
	for _, cm := range s.ConfigMaps {
		if cm.Name == "" {
			return fmt.Errorf("invalid ConfigMap name")
		}
		if _, ok := maps[cm.Name]; ok {
			return fmt.Errorf("duplicate ConfigMap %s", cm.Name)
		}
		maps[cm.Name] = cm
	}
	if len(refs) != len(maps) {
		return fmt.Errorf("backup ConfigMaps do not match references")
	}
	for name, keys := range refs {
		cm, ok := maps[name]
		if !ok {
			return fmt.Errorf("missing backup ConfigMap %s", name)
		}
		for _, key := range keys {
			if _, ok := cm.Data[key]; !ok {
				return fmt.Errorf("backup ConfigMap %s missing key %s", name, key)
			}
		}
	}
	for _, data := range s.ConfigMaps {
		cm := &corev1.ConfigMap{}
		key := client.ObjectKey{Namespace: s.Namespace, Name: data.Name}
		err := c.Get(ctx, key, cm)
		if apierrors.IsNotFound(err) {
			cm = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: data.Name, Namespace: s.Namespace}, Data: data.Data, BinaryData: data.BinaryData}
			if err := c.Create(ctx, cm); err != nil {
				return fmt.Errorf("create ConfigMap %s: %w", data.Name, err)
			}
		} else if err != nil {
			return err
		} else {
			cm.Data = data.Data
			cm.BinaryData = data.BinaryData
			if err := c.Update(ctx, cm); err != nil {
				return fmt.Errorf("update ConfigMap %s: %w", data.Name, err)
			}
		}
	}
	sensor := &unstructured.Unstructured{}
	sensor.SetGroupVersionKind(sensorKind)
	key := client.ObjectKey{Namespace: s.Namespace, Name: s.Name}
	err = c.Get(ctx, key, sensor)
	if apierrors.IsNotFound(err) {
		sensor = &unstructured.Unstructured{Object: map[string]interface{}{"apiVersion": sensorKind.GroupVersion().String(), "kind": sensorKind.Kind, "metadata": map[string]interface{}{"name": s.Name, "namespace": s.Namespace}, "spec": runtime.DeepCopyJSONValue(s.Spec)}}
		if err := c.Create(ctx, sensor); err != nil {
			return fmt.Errorf("create sensor: %w", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	sensor.Object["spec"] = runtime.DeepCopyJSONValue(s.Spec)
	if err := c.Update(ctx, sensor); err != nil {
		return fmt.Errorf("update sensor: %w", err)
	}
	return nil
}
