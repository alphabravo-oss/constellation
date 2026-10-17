package dpi

import (
	"encoding/binary"
	"unicode/utf8"
)

// parseKafka decodes the Kafka request header: size(4) + apiKey(2) + apiVersion(2)
// + correlationID(4) + clientID(short string). Body interpretation depends on apiKey
// + version; for now we only surface the header which is enough for WAF to enforce
// "no consumer groups outside this allowlist" or "no DescribeAcls from this pod".
func parseKafka(flow Flow, dir Direction, payload []byte) *L7Event {
	if len(payload) < 4+2+2+4+2 {
		return nil
	}
	size := binary.BigEndian.Uint32(payload[0:4])
	if size < 10 || size > 1<<24 || uint64(size)+4 > uint64(len(payload)) {
		return nil
	}
	frame := payload[:int(size)+4]
	var header struct {
		APIKey      int16
		APIVersion  int16
		Correlation int32
		ClientLen   int16
	}
	if _, err := binary.Decode(frame[4:14], binary.BigEndian, &header); err != nil {
		return nil
	}
	if header.APIKey < 0 || header.APIKey > 100 || header.APIVersion < 0 || header.APIVersion > 20 || header.ClientLen < -1 {
		return nil
	}
	cid := ""
	if header.ClientLen > 0 {
		end := 14 + int(header.ClientLen)
		if end > len(frame) || !utf8.Valid(frame[14:end]) {
			return nil
		}
		cid = string(frame[14:end])
	}
	return &L7Event{
		Flow: flow, Protocol: "kafka", Dir: dir,
		Kafka: &KafkaEvent{APIKey: header.APIKey, APIVersion: header.APIVersion, Correlation: header.Correlation, ClientID: cid},
	}
}
