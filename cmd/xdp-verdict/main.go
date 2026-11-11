//go:build linux

// xdp-verdict attaches a bounded IPv4 flow cache to a dedicated interface and
// learns short-lived entries only from blocked Suricata EVE alerts.
package main

import (
	"bytes"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/instagrim-dev/yas-suricata-operator/internal/xdpverdict"
	"golang.org/x/sys/unix"
)

//go:embed bpf/xdp.o
var object []byte

type value struct {
	Expires uint64
	Hits    uint64
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	iface := flag.String("interface", "", "dedicated ingress interface")
	eve := flag.String("eve", "/var/log/suricata/eve.json", "Suricata EVE log")
	ttl := flag.Duration("ttl", 30*time.Second, "flow cache TTL (1s to 5m)")
	flag.Parse()
	if *iface == "" || *ttl < time.Second || *ttl > 5*time.Minute {
		return fmt.Errorf("interface and TTL between 1s and 5m are required")
	}
	device, err := net.InterfaceByName(*iface)
	if err != nil {
		return fmt.Errorf("interface: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return fmt.Errorf("load XDP spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load XDP resources: %w", err)
	}
	defer coll.Close()
	attached, err := link.AttachXDP(link.XDPOptions{Program: coll.Programs["xdp_verdict"], Interface: device.Index, Flags: link.XDPGenericMode})
	if err != nil {
		return fmt.Errorf("attach XDP (existing program is not replaced): %w", err)
	}
	defer attached.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("XDP verdict cache attached; waiting for new EVE alerts")
	return xdpverdict.Tail(ctx, *eve, 200*time.Millisecond, func(line []byte) {
		key, ok := xdpverdict.FlowFromEVE(line)
		if !ok {
			return
		}
		var now unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
			log.Printf("monotonic clock: %v", err)
			return
		}
		entry := value{Expires: uint64(now.Nano()) + uint64(*ttl)}
		if err := coll.Maps["drops"].Put(key, entry); err != nil {
			log.Printf("cache update failed: %v", err)
		}
	})
}
