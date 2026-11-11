package main

import (
	"github.com/instagrim-dev/yas-suricata-operator/internal/controller"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme, Metrics: server.Options{BindAddress: "0"}, HealthProbeBindAddress: ":8081", LeaderElection: true, LeaderElectionID: "suricata-operator.yas.ohbmo.com"})
	if err != nil {
		os.Exit(1)
	}
	if err = (&controller.Reconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).Setup(mgr); err != nil {
		os.Exit(1)
	}
	if err = mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		os.Exit(1)
	}
	if err = mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		os.Exit(1)
	}
}
