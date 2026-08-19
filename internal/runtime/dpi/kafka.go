package dpi

import "encoding/binary"

// parseKafka decodes the Kafka request header: size(4) + apiKey(2) + apiVersion(2)
// + correlationID(4) + clientID(short string). Body interpretation depends on apiKey
// + version; for now we only surface the header which is enough for WAF to enforce
// "no consumer groups outside this allowlist" or "no DescribeAcls from this pod".
func parseKafka(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) < 4+2+2+4+2 {
		return nil
	}
	size := int(binary.BigEndian.Uint32(payload[0:4]))
	if size <= 0 || size > 1<<24 || size+4 > len(payload) {
		return nil
	}
	apiKey := int16(binary.BigEndian.Uint16(payload[4:6]))
	apiVer := int16(binary.BigEndian.Uint16(payload[6:8]))
	if apiKey < 0 || apiKey > 100 || apiVer < 0 || apiVer > 20 {
		return nil
	}
	corr := int32(binary.BigEndian.Uint32(payload[8:12]))
	cidLen := int16(binary.BigEndian.Uint16(payload[12:14]))
	cid := ""
	if cidLen > 0 && 14+int(cidLen) <= len(payload) {
		cid = string(payload[14 : 14+int(cidLen)])
	}
	return &L7Event{
		Flow: flow, Protocol: "kafka", Dir: dir,
		Kafka: &KafkaEvent{APIKey: apiKey, APIVersion: apiVer, Correlation: corr, ClientID: cid},
	}
}
