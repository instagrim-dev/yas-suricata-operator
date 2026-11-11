package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
	if image == "" || claim == "" || file == "" {
		return ctrl.Result{}, fmt.Errorf("image, capture.claimName, and capture.file are required")
	}
	if strings.HasPrefix(file, "/") || path.Clean(file) != file || file == ".." || strings.HasPrefix(file, "../") {
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
	rulesName, rulesKey, rulesHash, err := r.configMapReference(ctx, s, "rulesFileRef")
	if err != nil {
		return ctrl.Result{}, err
	}

	name := s.GetName()
	namespace := s.GetNamespace()
	labels := map[string]string{"app.kubernetes.io/name": "suricata", "app.kubernetes.io/instance": name}
	d := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	_, err = controllerutil.CreateOrUpdate(ctx, r.Client, d, func() error {
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
		engine := &pod.Containers[0]
		engine.Name = "suricata"
		engine.Image = image
		engine.Command = []string{"suricata"}
		engine.Args = []string{"-r", "/capture/" + file, "--pcap-file-continuous"}
		disableChecksum, _, _ := unstructured.NestedBool(s.Object, "spec", "disableChecksumValidation")
		if disableChecksum {
			engine.Args = append(engine.Args, "-k", "none")
		}
		engine.VolumeMounts = []corev1.VolumeMount{{Name: "capture", MountPath: "/capture"}}
		pod.Volumes = []corev1.Volume{{Name: "capture", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claim}}}}
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

		if rulesName != "" {
			d.Spec.Template.Annotations["suricata.yas.ohbmo.com/rules-sha256"] = rulesHash
			engine.Args = append(engine.Args, "-s", "/etc/suricata/operator-rules/rules.rules")
			engine.VolumeMounts = append(engine.VolumeMounts, corev1.VolumeMount{Name: "sensor-rule-file", MountPath: "/etc/suricata/operator-rules", ReadOnly: true})
			pod.Volumes = append(pod.Volumes, corev1.Volume{Name: "sensor-rule-file", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: rulesName}, Items: []corev1.KeyToPath{{Key: rulesKey, Path: "rules.rules"}}}}})
		}

		if schedule != "" {
			d.Spec.Template.Spec.Containers[0].VolumeMounts = append(d.Spec.Template.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "rules", MountPath: "/var/lib/suricata/rules"})
			d.Spec.Template.Spec.Volumes = append(d.Spec.Template.Spec.Volumes, corev1.Volume{Name: "rules", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: rulesClaim}}})
		}
		return nil
	})
	if err != nil {
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
	return ctrl.NewControllerManagedBy(mgr).For(NewSensor()).Owns(&appsv1.Deployment{}).Owns(&batchv1.CronJob{}).Watches(&corev1.ConfigMap{}, handler.EnqueueRequestsFromMapFunc(r.sensorsForConfigMap)).Complete(r)
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
		name, _, _ := unstructured.NestedString(sensor.Object, "spec", "configRef", "name")
		rules, _, _ := unstructured.NestedString(sensor.Object, "spec", "rulesFileRef", "name")
		if name == obj.GetName() || rules == obj.GetName() {
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
