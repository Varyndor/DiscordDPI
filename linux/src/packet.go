package main

import "encoding/binary"

const (
	protoTCP  = 6
	protoUDP  = 17
	fragSize  = 2
	fakeTTL   = 5
	windowTwo = 2
)

// www.w3.org sunucu adi tasiyan TLS istemci merhabasi. DPI bunu gercek
// el sikisma sayar. Yasam suresi 5 oldugu icin siteye ulasmaz.
var fakeHello = []byte{
	0x16, 0x03, 0x01, 0x00, 0x64, 0x01, 0x00, 0x00, 0x60, 0x03, 0x03,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00,
	0x00, 0x04, 0x13, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x33, 0x00,
	0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x77, 0x77, 0x77,
	0x2e, 0x77, 0x33, 0x2e, 0x6f, 0x72, 0x67, 0x00, 0x17, 0x00, 0x00,
	0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02,
	0x00, 0x1d, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
}

type pkt struct {
	raw     []byte
	ip4     bool
	l4      int
	data    int
	srcPort uint16
	dstPort uint16
	seq     uint32
	syn     bool
	ack     bool
	payload []byte
}

func parse(raw []byte) (pkt, bool) {
	var p pkt
	p.raw = raw
	if len(raw) < 40 {
		return p, false
	}
	switch raw[0] >> 4 {
	case 4:
		p.l4 = int(raw[0]&0x0f) * 4
		if p.l4 < 20 || len(raw) < p.l4 || (raw[9] != protoTCP && raw[9] != protoUDP) {
			return p, false
		}
		p.ip4 = true
	case 6:
		if raw[6] != protoTCP && raw[6] != protoUDP {
			return p, false
		}
		p.l4 = 40
	default:
		return p, false
	}
	udp := (p.ip4 && raw[9] == protoUDP) || (!p.ip4 && raw[6] == protoUDP)
	p.srcPort = binary.BigEndian.Uint16(raw[p.l4 : p.l4+2])
	p.dstPort = binary.BigEndian.Uint16(raw[p.l4+2 : p.l4+4])
	if udp {
		if len(raw) < p.l4+8 {
			return p, false
		}
		p.data = p.l4 + 8
		p.payload = raw[p.data:]
		return p, true
	}
	if len(raw) < p.l4+20 {
		return p, false
	}
	p.seq = binary.BigEndian.Uint32(raw[p.l4+4 : p.l4+8])
	off := int(raw[p.l4+12]>>4) * 4
	if off < 20 || len(raw) < p.l4+off {
		return p, false
	}
	flags := raw[p.l4+13]
	p.syn = flags&0x02 != 0
	p.ack = flags&0x10 != 0
	p.data = p.l4 + off
	p.payload = raw[p.data:]
	return p, true
}

func (p pkt) udp() bool {
	if p.ip4 {
		return p.raw[9] == protoUDP
	}
	return len(p.raw) > 6 && p.raw[6] == protoUDP
}

func (p pkt) setLen(buf []byte, total int) {
	if p.ip4 {
		binary.BigEndian.PutUint16(buf[2:4], uint16(total))
		return
	}
	binary.BigEndian.PutUint16(buf[4:6], uint16(total-40))
}

func (p pkt) setTTL(buf []byte, ttl byte) {
	if p.ip4 {
		buf[8] = ttl
		return
	}
	buf[7] = ttl
}

func ipSum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xFFFF {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

func transportSum(p pkt, buf []byte, off int) uint16 {
	var s uint32
	add := func(v uint16) { s += uint32(v) }
	if p.ip4 {
		add(binary.BigEndian.Uint16(buf[12:14]))
		add(binary.BigEndian.Uint16(buf[14:16]))
		add(binary.BigEndian.Uint16(buf[16:18]))
		add(binary.BigEndian.Uint16(buf[18:20]))
		add(uint16(buf[9]))
	} else {
		for i := 8; i < 40; i += 2 {
			add(binary.BigEndian.Uint16(buf[i:]))
		}
		add(uint16(buf[6]))
	}
	add(uint16(len(buf) - off))
	for i := off; i+1 < len(buf); i += 2 {
		add(binary.BigEndian.Uint16(buf[i:]))
	}
	if (len(buf)-off)%2 == 1 {
		add(uint16(buf[len(buf)-1]) << 8)
	}
	for s > 0xFFFF {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

func finish(p pkt, buf []byte) {
	off := p.l4
	if p.ip4 {
		buf[10], buf[11] = 0, 0
		binary.BigEndian.PutUint16(buf[10:12], ipSum(buf[:off]))
	}
	if p.udp() {
		buf[off+6], buf[off+7] = 0, 0
		c := transportSum(p, buf, off)
		if c == 0 {
			c = 0xFFFF
		}
		binary.BigEndian.PutUint16(buf[off+6:off+8], c)
		return
	}
	buf[off+16], buf[off+17] = 0, 0
	binary.BigEndian.PutUint16(buf[off+16:off+18], transportSum(p, buf, off))
}

func u16(b []byte) int { return int(binary.BigEndian.Uint16(b)) }

func clientHelloSNI(data []byte) (string, bool) {
	if len(data) < 44 || data[0] != 0x16 || data[1] != 0x03 || data[5] != 0x01 {
		return "", false
	}
	i := 43
	if i >= len(data) {
		return "", false
	}
	i += 1 + int(data[i])
	if i+2 > len(data) {
		return "", false
	}
	i += 2 + u16(data[i:])
	if i+1 > len(data) {
		return "", false
	}
	i += 1 + int(data[i])
	if i+2 > len(data) {
		return "", false
	}
	extEnd := i + 2 + u16(data[i:])
	i += 2
	if extEnd > len(data) {
		extEnd = len(data)
	}
	for i+4 <= extEnd {
		typ := u16(data[i:])
		ln := u16(data[i+2:])
		i += 4
		if i+ln > extEnd {
			return "", false
		}
		if typ == 0 && ln >= 5 && data[i+2] == 0 {
			n := u16(data[i+3:])
			if n >= 3 && 5+n <= ln && hostOK(data[i+5:i+5+n]) {
				return string(data[i+5 : i+5+n]), true
			}
			return "", false
		}
		i += ln
	}
	return "", false
}

func hostOK(b []byte) bool {
	if len(b) < 3 || len(b) > 253 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

type flowKey struct {
	local [16]byte
	peer  [16]byte
	lp    uint16
	id    uint16
	v6    bool
}

func (p pkt) key() flowKey {
	var k flowKey
	k.lp = p.srcPort
	k.v6 = !p.ip4
	if p.ip4 {
		copy(k.local[:4], p.raw[12:16])
		copy(k.peer[:4], p.raw[16:20])
	} else {
		copy(k.local[:], p.raw[8:24])
		copy(k.peer[:], p.raw[24:40])
	}
	return k
}

func (p pkt) replyKey() flowKey {
	var k flowKey
	k.lp = p.dstPort
	k.v6 = !p.ip4
	if p.ip4 {
		copy(k.local[:4], p.raw[16:20])
		copy(k.peer[:4], p.raw[12:16])
	} else {
		copy(k.local[:], p.raw[24:40])
		copy(k.peer[:], p.raw[8:24])
	}
	return k
}

func (p pkt) dnsOutKey(id uint16) dnsFlow {
	var k dnsFlow
	k.lp = p.srcPort
	k.id = id
	k.v6 = !p.ip4
	if p.ip4 {
		copy(k.local[:4], p.raw[12:16])
	} else {
		copy(k.local[:], p.raw[8:24])
	}
	return k
}

func (p pkt) dnsInKey(id uint16) dnsFlow {
	var k dnsFlow
	k.lp = p.dstPort
	k.id = id
	k.v6 = !p.ip4
	if p.ip4 {
		copy(k.local[:4], p.raw[16:20])
	} else {
		copy(k.local[:], p.raw[24:40])
	}
	return k
}

func redirectDNS(p pkt) (dnsFlow, []byte, bool) {
	if !p.ip4 || !p.udp() || p.dstPort != 53 {
		return dnsFlow{}, nil, false
	}
	id, ok := discordQuery(p.payload)
	if !ok {
		return dnsFlow{}, nil, false
	}
	buf := append([]byte(nil), p.raw...)
	copy(buf[16:20], dns4)
	binary.BigEndian.PutUint16(buf[p.l4+2:p.l4+4], dnsPort)
	finish(p, buf)
	return p.dnsOutKey(id), buf, true
}

func restoreDNS(p pkt, pend dnsPend) []byte {
	buf := append([]byte(nil), p.raw...)
	copy(buf[12:16], pend.server[:4])
	binary.BigEndian.PutUint16(buf[p.l4:p.l4+2], 53)
	finish(p, buf)
	return buf
}

func fakePacket(p pkt) ([]byte, bool) {
	n := p.data + len(fakeHello)
	if n > 0xFFFF {
		return nil, false
	}
	buf := make([]byte, n)
	copy(buf, p.raw[:p.data])
	copy(buf[p.data:], fakeHello)
	p.setLen(buf, n)
	p.setTTL(buf, fakeTTL)
	finish(p, buf)
	return buf, true
}

func slicePacket(p pkt, from, to, seqAdd int) []byte {
	buf := make([]byte, p.data+(to-from))
	copy(buf, p.raw[:p.data])
	copy(buf[p.data:], p.payload[from:to])
	p.setLen(buf, len(buf))
	if seqAdd != 0 {
		binary.BigEndian.PutUint32(buf[p.l4+4:p.l4+8], p.seq+uint32(seqAdd))
	}
	finish(p, buf)
	return buf
}

// splitHello, gercek merhabayi once kuyruk sonra bas olarak verir.
func splitHello(p pkt) [][]byte {
	if len(p.payload) <= fragSize {
		out := append([]byte(nil), p.raw...)
		finish(p, out)
		return [][]byte{out}
	}
	return [][]byte{
		slicePacket(p, fragSize, len(p.payload), fragSize),
		slicePacket(p, 0, fragSize, 0),
	}
}

func shrinkWindow(p pkt) []byte {
	buf := append([]byte(nil), p.raw...)
	binary.BigEndian.PutUint16(buf[p.l4+14:p.l4+16], windowTwo)
	q, _ := parse(buf)
	finish(q, buf)
	return buf
}
