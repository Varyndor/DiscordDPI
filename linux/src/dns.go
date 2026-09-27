package main

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

const (
	dnsPort     = 1253
	maxDNSTrack = 2048
)

var dns4 = net.IPv4(77, 88, 8, 8).To4()

type dnsFlow struct {
	local [16]byte
	lp    uint16
	id    uint16
	v6    bool
}

type dnsPend struct {
	id     uint16
	server [16]byte
	at     time.Time
}

type dnsTracker struct {
	m map[dnsFlow]dnsPend
}

func (t *dnsTracker) add(k dnsFlow, p dnsPend) {
	if len(t.m) > maxDNSTrack {
		cut := time.Now().Add(-15 * time.Second)
		for key, v := range t.m {
			if v.at.Before(cut) {
				delete(t.m, key)
			}
		}
	}
	t.m[k] = p
}

func (t *dnsTracker) take(k dnsFlow) (dnsPend, bool) {
	p, ok := t.m[k]
	if !ok || time.Since(p.at) > 15*time.Second {
		return dnsPend{}, false
	}
	delete(t.m, k)
	return p, true
}

func dnsName(data []byte, off int) (string, int, bool) {
	var b strings.Builder
	consumed := 0
	jumps := 0
	for {
		if off >= len(data) {
			return "", 0, false
		}
		n := int(data[off])
		if n == 0 {
			if jumps == 0 {
				consumed++
			}
			return b.String(), consumed, true
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(data) {
				return "", 0, false
			}
			if jumps == 0 {
				consumed += 2
			}
			jumps++
			if jumps > 8 {
				return "", 0, false
			}
			off = int(binary.BigEndian.Uint16(data[off:]) & 0x3FFF)
			continue
		}
		if n&0xC0 != 0 || off+1+n > len(data) {
			return "", 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(data[off+1 : off+1+n])
		off += 1 + n
		if jumps == 0 {
			consumed += 1 + n
		}
		if b.Len() > 253 {
			return "", 0, false
		}
	}
}

// discordQuery, paketin ilk sorusu Discord adina aitse dogrudur.
// Cevap, ek soru ve birden fazla soru olan paketler disarida kalir.
func discordQuery(payload []byte) (uint16, bool) {
	if len(payload) < 12 {
		return 0, false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&0x8000 != 0 || binary.BigEndian.Uint16(payload[4:6]) != 1 {
		return 0, false
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0 {
		return 0, false
	}
	name, n, ok := dnsName(payload, 12)
	if !ok || 12+n+4 > len(payload) {
		return 0, false
	}
	if !discordHost(strings.ToLower(name)) {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[0:2]), true
}

func replyID(payload []byte) (uint16, bool) {
	if len(payload) < 12 || payload[2]&0x80 == 0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[0:2]), true
}
