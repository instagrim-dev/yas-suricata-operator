// suricata-backup exports or restores sensor configuration and referenced ConfigMaps.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/instagrim-dev/yas-suricata-operator/internal/backup"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	flags := flag.NewFlagSet("suricata-backup", flag.ContinueOnError)
	namespace := flags.String("namespace", "default", "sensor namespace (export)")
	name := flags.String("name", "", "sensor name (export)")
	file := flags.String("file", "", "backup JSON file")
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: suricata-backup export|restore --file PATH [--namespace NS --name NAME]")
	}
	action := os.Args[1]
	if action != "export" && action != "restore" {
		return fmt.Errorf("unknown action %q", action)
	}
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *file == "" {
		return fmt.Errorf("--file is required")
	}
	if action == "export" && *name == "" {
		return fmt.Errorf("--name is required")
	}
	config, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load Kubernetes configuration: %w", err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	c, err := client.New(config, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}
	ctx := context.Background()
	if action == "export" {
		snapshot, err := backup.Capture(ctx, c, types.NamespacedName{Name: *name, Namespace: *namespace})
		if err != nil {
			return err
		}
		contents, err := json.MarshalIndent(snapshot, "", "  ")
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Chmod(0600); err != nil {
			return err
		}
		if _, err := f.Write(append(contents, '\n')); err != nil {
			return err
		}
		return f.Close()
	}
	f, err := os.Open(*file)
	if err != nil {
		return err
	}
	defer f.Close()
	var snapshot backup.Snapshot
	if err := json.NewDecoder(f).Decode(&snapshot); err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	return backup.Restore(ctx, c, &snapshot)
}
