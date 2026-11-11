package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var SensorGVK = schema.GroupVersionKind{Group: "suricata.yas.ohbmo.com", Version: "v1alpha1", Kind: "SuricataSensor"}

func NewSensor() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(SensorGVK)
	return u
}

type Reconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	s := NewSensor()
	if err := r.Get(ctx, req.NamespacedName, s); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	image, _, _ := unstructured.NestedString(s.Object, "spec", "image")
	claim, _, _ := unstructured.NestedString(s.Object, "spec", "capture", "claimName")
	file, _, _ := unstructured.NestedString(s.Object, "spec", "capture", "file")
	iface, _, _ := unstructured.NestedString(s.Object, "spec", "capture", "interface")
	hostNetwork, _, _ := unstructured.NestedBool(s.Object, "spec", "capture", "hostNetwork")
	if image == "" || (iface == "" && (claim == "" || file == "")) || (iface != "" && (claim != "" || file != "")) {
		return ctrl.Result{}, fmt.Errorf("image and exactly one capture mode are required: interface or claimName/file")
	}
	if iface != "" && (len(iface) > 15 || strings.ContainsAny(iface, " /\t\n")) {
		return ctrl.Result{}, fmt.Errorf("invalid capture interface")
	}
	if iface == "" && (strings.HasPrefix(file, "/") || path.Clean(file) != file || file == ".." || strings.HasPrefix(file, "../")) {
		return ctrl.Result{}, fmt.Errorf("capture.file must be a clean relative path")
	}
	replicas, found, err := unstructured.NestedInt64(s.Object, "spec", "replicas")
	if err != nil {
		return ctrl.Result{}, err
	}
	if !found {
		replicas = 1
	}
	if replicas < 0 || replicas > 1 {
		return ctrl.Result{}, fmt.Errorf("replicas must be 0 or 1")
	}
	schedule, _, _ := unstructured.NestedString(s.Object, "spec", "rules", "updateSchedule")
	rulesClaim, _, _ := unstructured.NestedString(s.Object, "spec", "rules", "claimName")
	if schedule != "" && rulesClaim == "" {
		return ctrl.Result{}, fmt.Errorf("rules.claimName is required when rules.updateSchedule is set")
	}
	configName, configKey, configHash, err := r.configMapReference(ctx, s, "configRef")
	if err != nil {
		return ctrl.Result{}, err
	}
	metricsImage, _, _ := unstructured.NestedString(s.Object, "spec", "metrics", "exporterImage")
	metricsPort, metricsFound, metricsErr := unstructured.NestedInt64(s.Object, "spec", "metrics", "port")
	if metricsErr != nil {
		return ctrl.Result{}, metricsErr
	}
	if (metricsImage == "") != (!metricsFound) || (metricsFound && (metricsPort < 1 || metricsPort > 65535)) {
		return ctrl.Result{}, fmt.Errorf("metrics requires exporterImage and a port between 1 and 65535")
	}
	metricsArgs, _, err := unstructured.NestedStringSlice(s.Object, "spec", "metrics", "args")
	if err != nil {
		return ctrl.Result{}, err
	}
	serviceMonitor, _, _ := unstructured.NestedBool(s.Object, "spec", "metrics", "serviceMonitor")
	metricsPath, _, _ := unstructured.NestedString(s.Object, "spec", "metrics", "path")
	if metricsPath == "" {
		metricsPath = "/metrics"
	}
	if !strings.HasPrefix(metricsPath, "/") {
		return ctrl.Result{}, fmt.Errorf("metrics path must start with /")
	}
	rulesSources, rulesHash, err := r.ruleSources(ctx, s)
	if err != nil {
		return ctrl.Result{}, err
	}

	name := s.GetName()
	namespace := s.GetNamespace()
	labels := map[string]string{"app.kubernetes.io/name": "suricata", "app.kubernetes.io/instance": name}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	render := func() error {
		if err := controllerutil.SetControllerReference(s, d, r.Scheme); err != nil {
			return err
		}
		d.Labels = labels
		d.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		d.Spec.Replicas = ptr(int32(replicas))
		d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
		d.Spec.Template.Labels = labels
		pod := &d.Spec.Template.Spec
		if len(pod.Containers) == 0 {
			pod.Containers = []corev1.Container{{Name: "suricata"}}
		}
		pod.Containers = pod.Containers[:1]

		engine := &pod.Containers[0]
		engine.Name = "suricata"
		engine.Image = image
		engine.Resources = corev1.ResourceRequirements{}
		if requested, found, err := unstructured.NestedMap(s.Object, "spec", "resources"); err != nil {
			return err
		} else if found {
			data, err := json.Marshal(requested)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(data, &engine.Resources); err != nil {
				return fmt.Errorf("invalid resource requirements: %w", err)
			}
		}
		engine.Command = []string{"suricata"}
		if iface == "" {
			engine.Args = []string{"-r", "/capture/" + file, "--pcap-file-continuous"}
		} else {
			engine.Args = []string{"-i", iface}
		}
		disableChecksum, _, _ := unstructured.NestedBool(s.Object, "spec", "disableChecksumValidation")
		if disableChecksum {
			engine.Args = append(engine.Args, "-k", "none")
		}
		pod.NodeSelector = nil
		if iface != "" {
			selector, _, err := unstructured.NestedStringMap(s.Object, "spec", "capture", "nodeSelector")
			if err != nil {
				return err
			}
			if selector == nil {
				selector = map[string]string{}
			}
			if os, ok := selector["kubernetes.io/os"]; ok && os != "linux" {
				return fmt.Errorf("live capture requires Linux nodes")
			}
			selector["kubernetes.io/os"] = "linux"
			pod.NodeSelector = selector
		}
		pod.HostNetwork = iface != "" && hostNetwork
		pod.DNSPolicy = corev1.DNSClusterFirst
		engine.SecurityContext = nil
		engine.VolumeMounts = nil
		pod.Volumes = nil
		if iface == "" {
			engine.VolumeMounts = []corev1.VolumeMount{{Name: "capture", MountPath: "/capture"}}
			pod.Volumes = []corev1.Volume{{Name: "capture", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}}
		} else {
			engine.SecurityContext = &corev1.SecurityContext{Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"NET_RAW", "NET_ADMIN"}}}
			if hostNetwork {
				pod.DNSPolicy = corev1.DNSClusterFirstWithHostNet
			}
		}
		if d.Spec.Template.Annotations == nil {
			d.Spec.Template.Annotations = map[string]string{}
		}
		delete(d.Spec.Template.Annotations, "suricata.yas.ohbmo.com/config-sha256")
		delete(d.Spec.Template.Annotations, "suricata.yas.ohbmo.com/rules-sha256")
		if configName != "" {
			d.Spec.Template.Annotations["suricata.yas.ohbmo.com/config-sha256"] = configHash
			engine.Args = append(engine.Args, "-c", "/etc/suricata/operator/suricata.yaml")
			engine.VolumeMounts = append(engine.VolumeMounts, corev1.VolumeMount{Name: "sensor-config", MountPath: "/etc/suricata/operator", ReadOnly: true})
			pod.Volumes = append(pod.Volumes, corev1.Volume{Name: "sensor-config", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: configName}, Items: []corev1.KeyToPath{{Key: configKey, Path: "suricata.yaml"}}}}})
		}

		if len(rulesSources) > 0 {
			d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] = rulesHash
			projections := make([]corev1.VolumeProjection, 0, len(rulesSources))
			for i, source := range rulesSources {
				filename := fmt.Sprintf("%03d.rules", i)
				if len(rulesSources) == 1 {
					filename = "rules.rules"
				}
				projection := corev1.VolumeProjection{}
				if source.kind == "Secret" {
					projection.Secret = &corev1.SecretProjection{LocalObjectReference: corev1.LocalObjectReference{Name: source.name}, Items: []corev1.KeyToPath{{Key: source.key, Path: filename}}}
				} else {
					projection.ConfigMap = &corev1.ConfigMapProjection{LocalObjectReference: corev1.LocalObjectReference{Name: source.name}, Items: []corev1.KeyToPath{{Key: source.key, Path: filename}}}
				}
				projections = append(projections, projection)
			}
			rulesPath := "/etc/suricata/operator-rules/*.rules"
			if len(rulesSources) == 1 {
				rulesPath = "/etc/suricata/operator-rules/rules.rules"
			}
			engine.Args = append(engine.Args, "-s", rulesPath)
			engine.VolumeMounts = append(engine.VolumeMounts, corev1.VolumeMount{Name: "sensor-rule-file", MountPath: "/etc/suricata/operator-rules", ReadOnly: true})
			pod.Volumes = append(pod.Volumes, corev1.Volume{Name: "sensor-rule-file", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: projections}}})
		}

		if metricsImage != "" {
			pod.Containers = append(pod.Containers, corev1.Container{Name: "metrics-exporter", Image: metricsImage, Args: metricsArgs, Ports: []corev1.ContainerPort{{Name: "metrics", ContainerPort: int32(metricsPort)}}})
		}
		if schedule != "" {
			d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "rules", MountPath: "/var/lib/suricata/rules"})
			d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, corev1.Volume{Name: "rules", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: rulesClaim}}})
		}
		return nil
	}
	if iface == "" {
		_, err = controllerutil.CreateOrUpdate(ctx, r.Client, d, render)
		if err == nil {
			err = removeOwned(ctx, r.Client, s, &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
		}
	} else if replicas == 0 {
		err = removeOwned(ctx, r.Client, s, &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
		if err == nil {
			err = removeOwned(ctx, r.Client, s, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
		}
	} else {
		if err = render(); err == nil {
			ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
			_, err = controllerutil.CreateOrUpdate(ctx, r.Client, ds, func() error {
				if err := controllerutil.SetControllerReference(s, ds, r.Scheme); err != nil {
					return err
				}
				ds.Labels = labels
				ds.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
				ds.Spec.Template = d.Spec.Template
				return nil
			})
		}
		if err == nil {
			err = removeOwned(ctx, r.Client, s, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}})
		}
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if err := r.reconcileMetrics(ctx, s, labels, metricsImage, int32(metricsPort), serviceMonitor, metricsPath); err != nil {
		return ctrl.Result{}, err
	}
	// Rules update is deliberately opt-in: it requires the specified image to
	// include suricata-update and a writable PVC shared with the engine.
	job := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: name + "-rules", Namespace: namespace}}
	if schedule == "" {
		if err := r.Get(ctx, client.ObjectKeyFromObject(job), job); err != nil {
			if apierrors.IsNotFound(err) {
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, err
		}
		if metav1.IsControlledBy(job, s) {
			if err := r.Delete(ctx, job, client.Preconditions{UID: ptr(job.UID), ResourceVersion: ptr(job.ResourceVersion)}); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, job, func() error {
		if err := controllerutil.SetControllerReference(s, job, r.Scheme); err != nil {
			return err
		}
		job.Spec.Schedule = schedule
		job.Spec.Suspend = ptr(replicas == 0)
		job.Spec.ConcurrencyPolicy = batchv1.ForbidConcurrent
		pod := &job.Spec.JobTemplate.Spec.Template.Spec
		pod.RestartPolicy = corev1.RestartPolicyOnFailure
		if len(pod.Containers) == 0 {
			pod.Containers = []corev1.Container{{Name: "update"}}
		}
		update := &pod.Containers[0]
		update.Name = "update"
		update.Image = image
		update.Command = []string{"suricata-update"}
		update.VolumeMounts = []corev1.VolumeMount{{Name: "rules", MountPath: "/var/lib/suricata/rules"}}
		pod.Volumes = []corev1.Volume{{Name: "rules", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: rulesClaim}}}}

		return nil
	})
	return ctrl.Result{}, err
}
func ptr[T any](v T) *T { return &v }
func (r *Reconciler) Setup(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(NewSensor()).Owns(&appsv1.Deployment{}).Owns(&appsv1.DaemonSet{}).Owns(&corev1.Service{}).Owns(&batchv1.CronJob{}).Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.sensorsForConfigMap)).Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.sensorsForConfigMap)).Complete(r)
}

// sensorsForConfigMap requeues only sensors in the same namespace referencing the changed configuration.
func (r *Reconciler) sensorsForConfigMap(ctx context.Context, obj client.Object) []reconcile.Request {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(SensorGVK.GroupVersion().WithKind("SuricataSensorList"))
	if err := r.List(ctx, list, client.InNamespace(obj.GetNamespace())); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "unable to find sensors for changed ConfigMap", "namespace", obj.GetNamespace(), "name", obj.GetName())
		return nil
	}
	requests := make([]reconcile.Request, 0)
	for i := range list.Items {
		sensor := &list.Items[i]
		_, isSecret := obj.(*corev1.Secret)
		name, _, _ := unstructured.NestedString(sensor.Object, "spec", "configRef", "name")
		rules, _, _ := unstructured.NestedString(sensor.Object, "spec", "rulesFileRef", "name")
		match := !isSecret && (name == obj.GetName() || rules == obj.GetName())
		refs, _, _ := unstructured.NestedSlice(sensor.Object, "spec", "rulesFileRefs")
		for _, raw := range refs {
			if ref, ok := raw.(map[string]interface{}); ok {
				kind, _ := ref["kind"].(string)
				if ref["name"] == obj.GetName() && ((isSecret && kind == "Secret") || (!isSecret && kind != "Secret")) {
					match = true
					break
				}
			}
		}
		if match {
			requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(sensor)})
		}
	}
	return requests
}

func (r *Reconciler) configMapReference(ctx context.Context, sensor *unstructured.Unstructured, field string) (string, string, string, error) {
	name, _, _ := unstructured.NestedString(sensor.Object, "spec", field, "name")
	key, _, _ := unstructured.NestedString(sensor.Object, "spec", field, "key")
	if (name == "") != (key == "") {
		return "", "", "", fmt.Errorf("%s requires both name and key", field)
	}
	if name == "" {
		return "", "", "", nil
	}
	cm := &corev1.ConfigMap{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: sensor.GetNamespace(), Name: name}, cm); err != nil {
		return "", "", "", fmt.Errorf("get %s: %w", field, err)
	}
	data, ok := cm.Data[key]
	if !ok {
		return "", "", "", fmt.Errorf("%s config map %q has no data key %q", field, name, key)
	}
	sum := sha256.Sum256([]byte(data))
	return name, key, hex.EncodeToString(sum[:]), nil
}

func removeOwned(ctx context.Context, c client.Client, sensor *unstructured.Unstructured, obj client.Object) error {
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !metav1.IsControlledBy(obj, sensor) {
		return fmt.Errorf("refusing to remove %T %s/%s owned by another resource", obj, obj.GetNamespace(), obj.GetName())
	}
	return client.IgnoreNotFound(c.Delete(ctx, obj, client.Preconditions{UID: ptr(obj.GetUID()), ResourceVersion: ptr(obj.GetResourceVersion())}))
}

type ruleSource struct{ kind, name, key string }

func (r *Reconciler) ruleSources(ctx context.Context, sensor *unstructured.Unstructured) ([]ruleSource, string, error) {
	refs := []ruleSource{}
	name, _, _ := unstructured.NestedString(sensor.Object, "spec", "rulesFileRef", "name")
	key, _, _ := unstructured.NestedString(sensor.Object, "spec", "rulesFileRef", "key")
	if (name == "") != (key == "") {
		return nil, "", fmt.Errorf("rulesFileRef requires name and key")
	}
	if name != "" {
		refs = append(refs, ruleSource{"ConfigMap", name, key})
	}
	entries, _, err := unstructured.NestedSlice(sensor.Object, "spec", "rulesFileRefs")
	if err != nil {
		return nil, "", err
	}
	for _, raw := range entries {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			return nil, "", fmt.Errorf("invalid rulesFileRefs entry")
		}
		n, nok := entry["name"].(string)
		k, kok := entry["key"].(string)
		if !nok || !kok || n == "" || k == "" {
			return nil, "", fmt.Errorf("rulesFileRefs requires name and key")
		}
		kind, _ := entry["kind"].(string)
		if kind == "" {
			kind = "ConfigMap"
		}
		if kind != "ConfigMap" && kind != "Secret" {
			return nil, "", fmt.Errorf("invalid rule source kind %s", kind)
		}
		refs = append(refs, ruleSource{kind, n, k})
	}
	hash := sha256.New()
	for _, ref := range refs {
		var data []byte
		if ref.kind == "Secret" {
			secret := &corev1.Secret{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: sensor.GetNamespace(), Name: ref.name}, secret); err != nil {
				return nil, "", fmt.Errorf("get rules Secret %s: %w", ref.name, err)
			}
			value, ok := secret.Data[ref.key]
			if !ok {
				return nil, "", fmt.Errorf("rules Secret %s missing key %s", ref.name, ref.key)
			}
			data = value
		} else {
			cm := &corev1.ConfigMap{}
			if err := r.Get(ctx, client.ObjectKey{Namespace: sensor.GetNamespace(), Name: ref.name}, cm); err != nil {
				return nil, "", fmt.Errorf("get rules ConfigMap %s: %w", ref.name, err)
			}
			value, ok := cm.Data[ref.key]
			if !ok {
				return nil, "", fmt.Errorf("rules ConfigMap %s missing key %s", ref.name, ref.key)
			}
			data = []byte(value)
		}
		fmt.Fprintf(hash, "%d:%s%d:%s%d:%s%d:", len(ref.kind), ref.kind, len(ref.name), ref.name, len(ref.key), ref.key, len(data))
		_, _ = hash.Write(data)
	}
	return refs, hex.EncodeToString(hash.Sum(nil)), nil
}

func (r *Reconciler) reconcileMetrics(ctx context.Context, sensor *unstructured.Unstructured, labels map[string]string, image string, port int32, monitor bool, metricsPath string) error {
	name := sensor.GetName() + "-metrics"
	namespace := sensor.GetNamespace()
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	monitorGVK := schema.GroupVersionKind{Group: "monitoring.coreos.com", Version: "v1", Kind: "ServiceMonitor"}
	sm := &unstructured.Unstructured{}
	sm.SetGroupVersionKind(monitorGVK)
	sm.SetName(name)
	sm.SetNamespace(namespace)
	if image == "" {
		if err := removeOwned(ctx, r.Client, sensor, svc); err != nil {
			return err
		}
		if err := removeOwned(ctx, r.Client, sensor, sm); err != nil && !meta.IsNoMatchError(err) && !runtime.IsNotRegisteredError(err) {
			return err
		}
		return nil
	}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		if err := controllerutil.SetControllerReference(sensor, svc, r.Scheme); err != nil {
			return err
		}
		svc.Labels = labels
		svc.Spec.Selector = labels
		svc.Spec.Ports = []corev1.ServicePort{{Name: "metrics", Port: port, TargetPort: intstr.FromString("metrics")}}
		return nil
	})
	if err != nil {
		return err
	}
	if !monitor {
		if err := removeOwned(ctx, r.Client, sensor, sm); err != nil && !meta.IsNoMatchError(err) && !runtime.IsNotRegisteredError(err) {
			return err
		}
		return nil
	}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, sm, func() error {
		if err := controllerutil.SetControllerReference(sensor, sm, r.Scheme); err != nil {
			return err
		}
		sm.SetLabels(labels)
		sm.Object["spec"] = map[string]interface{}{"selector": map[string]interface{}{"matchLabels": map[string]interface{}{"app.kubernetes.io/name": "suricata", "app.kubernetes.io/instance": sensor.GetName()}}, "namespaceSelector": map[string]interface{}{"matchNames": []interface{}{namespace}}, "endpoints": []interface{}{map[string]interface{}{"port": "metrics", "path": metricsPath}}}
		return nil
	})
	if meta.IsNoMatchError(err) {
		return fmt.Errorf("ServiceMonitor requested but its CRD is not installed: %w", err)
	}
	return err
}
