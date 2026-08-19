package handler

// NeuVectorThreatName maps NeuVector's THRT_ID_* numeric IDs (defined in
// third_party/neuvector/defs.h) to the human-readable label used in the UI.
// The list mirrors the upstream constants verbatim so an operator looking at
// our UI can search the NeuVector docs/source for the same name.
//
// IDs that are not yet mapped fall back to "threat_<id>" so the column is
// always populated. New NeuVector releases that add IDs need a one-line
// addition here.
func NeuVectorThreatName(id uint32) string {
	switch id {
	case 0:
		return ""
	// Volume-based flood/DoS detectors fired by the shared dp binary. These
	// live below the 2000-range pattern signatures in NeuVector's defs.h and
	// were previously unmapped, rendering as "threat_1001/1002/1003".
	case 1001:
		return "SYN_FLOOD"
	case 1002:
		return "ICMP_FLOOD"
	case 1003:
		return "IP_SRC_SESSION"
	case 2000:
		return "HTTP_NEG_LEN"
	case 2001:
		return "HTTP_REQ_LARGE"
	case 2002:
		return "HTTP_BAD_VERSION"
	case 2003:
		return "DNS_MAX_LABEL"
	case 2004:
		return "TCP_BAD_FLAGS"
	case 2005:
		return "TCP_SMURF"
	case 2006:
		return "PING_DEATH"
	case 2007:
		return "DNS_LOOP_PTR"
	case 2008:
		return "SSH_VER_1"
	case 2009:
		return "SSL_HEARTBLEED"
	case 2010:
		return "SSL_CIPHER_OVF"
	case 2011:
		return "SSL_VER_2OR3"
	case 2012:
		return "SSL_TLS_1DOT0"
	case 2013:
		return "HTTP_NEG_LEN_2"
	case 2014:
		return "HTTP_SMUGGLING"
	case 2015:
		return "HTTP_SLOWLORIS"
	case 2016:
		return "TCP_SMALL_WINDOW"
	case 2017:
		return "DNS_OVERFLOW"
	case 2018:
		return "MYSQL_ACCESS_DENY"
	case 2019:
		return "DNS_ZONE_TRANSFER"
	case 2020:
		return "ICMP_TUNNELING"
	case 2021:
		return "DNS_TYPE_NULL"
	case 2022:
		return "SQL_INJECTION"
	case 2023:
		return "APACHE_STRUTS_RCE"
	case 2024:
		return "DNS_TUNNELING"
	case 2025:
		return "TCP_SMALL_MSS"
	case 2026:
		return "K8S_EXTIP_MITM"
	case 2027:
		return "SSL_TLS_1DOT1"
	}
	return formatUnknownThreat(id)
}

func formatUnknownThreat(id uint32) string {
	// One-off allocator: only called when we hit an unmapped ID, which by
	// definition is rare. fmt would do, but keeping it allocation-free
	// matters in case dp ever spams an unknown ID in a hot loop.
	const prefix = "threat_"
	var buf [16]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = byte('0' + id%10)
		id /= 10
	}
	if i == len(buf) {
		i--
		buf[i] = '0'
	}
	return prefix + string(buf[i:])
}
