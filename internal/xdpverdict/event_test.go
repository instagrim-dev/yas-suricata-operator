package xdpverdict

import (
	"encoding/binary"
	"testing"
)

func TestBlockedIPv4EventCreatesFlowKey(t *testing.T) {
	k, ok := FlowFromEVE([]byte(`{"event_type":"alert","src_ip":"10.77.0.1","dest_ip":"10.77.0.2","src_port":45000,"dest_port":4444,"proto":"UDP","alert":{"action":"blocked"}}`))
	if !ok || k[0] != 10 || k[3] != 1 || binary.BigEndian.Uint16(k[8:10]) != 45000 || k[12] != 17 {
		t.Fatalf("unexpected key %v %v", k, ok)
	}
}
func TestOtherEventsCannotCreateFlow(t *testing.T) {
	for _, v := range []string{`{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":1,"dest_port":2,"proto":"UDP","alert":{"action":"allowed"}}`, `{"event_type":"alert","src_ip":"::1","dest_ip":"10.0.0.2","src_port":1,"dest_port":2,"proto":"UDP","alert":{"action":"blocked"}}`, `{"event_type":"alert","src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":-1,"dest_port":2,"proto":"UDP","alert":{"action":"blocked"}}`} {
		if _, ok := FlowFromEVE([]byte(v)); ok {
			t.Fatalf("accepted %s", v)
		}
	}
}

func TestExplicitPassVerdictIsNotCached(t *testing.T) {
	line := []byte(`{"event_type":"alert","src_ip":"10.77.0.1","dest_ip":"10.77.0.2","src_port":45000,"dest_port":4444,"proto":"UDP","alert":{"action":"blocked"},"verdict":{"action":"pass"}}`)
	if _, ok := FlowFromEVE(line); ok {
		t.Fatal("explicit pass verdict cached")
	}
}
