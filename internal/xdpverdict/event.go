package xdpverdict

import (
	"encoding/binary"
	"encoding/json"
	"net"
)

// FlowFromEVE accepts only observed blocked IPv4 TCP/UDP alert tuples.
// It does not infer a verdict from a rule's presence or from an allowed alert.
func FlowFromEVE(data []byte) ([16]byte, bool) {
	var key [16]byte
	var event struct {
		Type            string `json:"event_type"`
		Source          string `json:"src_ip"`
		Destination     string `json:"dest_ip"`
		SourcePort      int    `json:"src_port"`
		DestinationPort int    `json:"dest_port"`
		Protocol        string `json:"proto"`
		Alert           struct {
			Action string `json:"action"`
		} `json:"alert"`
		Verdict *struct {
			Action string `json:"action"`
		} `json:"verdict"`
	}
	if json.Unmarshal(data, &event) != nil || event.Type != "alert" || event.Alert.Action != "blocked" || (event.Verdict != nil && event.Verdict.Action != "drop" && event.Verdict.Action != "reject") {
		return key, false
	}
	src, dst := net.ParseIP(event.Source).To4(), net.ParseIP(event.Destination).To4()
	if src == nil || dst == nil || event.SourcePort < 1 || event.SourcePort > 65535 || event.DestinationPort < 1 || event.DestinationPort > 65535 {
		return key, false
	}
	switch event.Protocol {
	case "UDP":
		key[12] = 17
	case "TCP":
		key[12] = 6
	default:
		return key, false
	}
	copy(key[0:4], src)
	copy(key[4:8], dst)
	binary.BigEndian.PutUint16(key[8:10], uint16(event.SourcePort))
	binary.BigEndian.PutUint16(key[10:12], uint16(event.DestinationPort))
	return key, true
}
