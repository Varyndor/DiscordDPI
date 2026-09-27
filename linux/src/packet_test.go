package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func ipv4(proto byte, src, dst []byte, l4 []byte) []byte {
	ip := make([]byte, 20+len(l4))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	copy(ip[20:], l4)
	return ip
}

func tcpSeg(sport, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint32(b[4:8], seq)
	b[12] = 5 << 4
	b[13] = flags
	binary.BigEndian.PutUint16(b[14:16], 65535)
	copy(b[20:], payload)
	return b
}

func udpSeg(sport, dport uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)))
	copy(b[8:], payload)
	return b
}

func dnsQuery(name string, flags uint16, questions uint16) []byte {
	b := []byte{
		0x12, 0x34,
		byte(flags >> 8), byte(flags),
		byte(questions >> 8), byte(questions),
		0, 0, 0, 0, 0, 0,
	}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

func TestSplitOrder(t *testing.T) {
	hello := append([]byte(nil), fakeHello...)
	hello[5+5] = 'a'
	raw := ipv4(protoTCP, []byte{10, 0, 0, 2}, []byte{1, 2, 3, 4}, tcpSeg(40000, 443, 1000, 0x18, hello))
	p, ok := parse(raw)
	if !ok {
		t.Fatal("okunamadi")
	}
	fake, ok := fakePacket(p)
	if !ok || fake[8] != fakeTTL {
		t.Fatal("sahte paket")
	}
	fp, _ := parse(fake)
	host, ok := clientHelloSNI(fp.payload)
	if !ok || host != "www.w3.org" || discordHost(host) {
		t.Fatalf("sahte ad %q", host)
	}
	parts := splitHello(p)
	if len(parts) != 2 {
		t.Fatal("iki parca beklenir")
	}
	tail, _ := parse(parts[0])
	head, _ := parse(parts[1])
	if head.seq != 1000 || tail.seq != 1002 {
		t.Fatalf("sira head=%d tail=%d", head.seq, tail.seq)
	}
	joined := append(append([]byte(nil), head.payload...), tail.payload...)
	if !bytes.Equal(joined, hello) {
		t.Fatal("parcalar merhabayi vermiyor")
	}
	if ipSum(parts[0][:20]) != 0 || ipSum(parts[1][:20]) != 0 {
		t.Fatal("ip toplamasi bozuk")
	}
}

func TestDNSOnlyDiscord(t *testing.T) {
	local := []byte{10, 0, 0, 2}
	router := []byte{10, 0, 0, 1}
	raw := ipv4(protoUDP, local, router, udpSeg(53000, 53, dnsQuery("updates.discord.com", 0x0100, 1)))
	p, ok := parse(raw)
	if !ok {
		t.Fatal("sorgu okunamadi")
	}
	key, out, ok := redirectDNS(p)
	if !ok {
		t.Fatal("discord sorgusu yonlenmedi")
	}
	op, _ := parse(out)
	if op.dstPort != dnsPort || !bytes.Equal(op.raw[16:20], dns4) {
		t.Fatal("hedef yandex degil")
	}
	if ipSum(out[:20]) != 0 {
		t.Fatal("ip toplamasi bozuk")
	}
	reply := ipv4(protoUDP, dns4, local, udpSeg(dnsPort, 53000, dnsQuery("updates.discord.com", 0x8180, 1)))
	rp, ok := parse(reply)
	id, _ := replyID(rp.payload)
	if !ok || rp.dnsInKey(id) != key {
		t.Fatal("cevap anahtari uyusmadi")
	}
	other := ipv4(protoUDP, local, router, udpSeg(53000, 53, dnsQuery("example.com", 0x0100, 1)))
	if _, _, ok := redirectDNS(mustParse(t, other)); ok {
		t.Fatal("example.com yonlendi")
	}
}

func TestRulesStayNarrow(t *testing.T) {
	text := rules()
	for _, want := range []string{
		"hook output", "hook input", "udp dport 53", "udp sport 1253",
		"ip saddr 77.88.8.8", "tcp dport 443", "tcp sport 443", "queue num 1 bypass",
		"meta mark 0xD1 accept", "tcp flags & (fin | rst | syn) == 0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("kuralda yok: %s", want)
		}
	}
	if strings.Contains(text, "policy drop") {
		t.Fatal("kural trafik dusuruyor")
	}
}

func TestHandleCases(t *testing.T) {
	local := []byte{10, 0, 0, 2}
	router := []byte{10, 0, 0, 1}
	flows := &flowTracker{m: map[flowKey]time.Time{}}
	dns := &dnsTracker{m: map[dnsFlow]dnsPend{}}

	plain := ipv4(protoUDP, local, router, udpSeg(53000, 53, dnsQuery("example.com", 0x0100, 1)))
	if v := handle(plain, true, flows, dns); len(v.out) != 0 {
		t.Fatal("example.com degisti")
	}

	query := ipv4(protoUDP, local, router, udpSeg(53000, 53, dnsQuery("updates.discord.com", 0x0100, 1)))
	v := handle(query, true, flows, dns)
	if v.kind != "dns" || len(v.out) != 1 {
		t.Fatal("discord sorgusu tek paket donmedi")
	}
	changed := handle(query, false, flows, dns)
	if len(changed.out) != 0 {
		t.Fatal("gelen yon sorgu sanildi")
	}

	reply := ipv4(protoUDP, dns4, local, udpSeg(dnsPort, 53000, dnsQuery("updates.discord.com", 0x8180, 1)))
	back := handle(reply, false, flows, dns)
	if len(back.out) != 1 {
		t.Fatal("cevap geri yazilmadi")
	}
	bp := mustParse(t, back.out[0])
	if bp.srcPort != 53 || !bytes.Equal(bp.raw[12:16], router) {
		t.Fatal("cevap kaynagi router olmadi")
	}
	if len(handle(reply, false, flows, dns).out) != 0 {
		t.Fatal("cevap ikinci kez yazildi")
	}

	site := ipv4(protoTCP, local, []byte{1, 2, 3, 4}, tcpSeg(40000, 443, 1000, 0x18, append([]byte(nil), fakeHello...)))
	if len(handle(site, true, flows, dns).out) != 0 {
		t.Fatal("www.w3.org discord sanildi")
	}

	hello := clientHello("gateway.discord.gg")
	if host, ok := clientHelloSNI(hello); !ok || host != "gateway.discord.gg" {
		t.Fatalf("deneme merhabasi okunamadi: %q %v len=%d %x", host, ok, len(hello), hello)
	}
	disc := ipv4(protoTCP, local, []byte{9, 9, 9, 9}, tcpSeg(41000, 443, 1000, 0x18, hello))
	got := handle(disc, true, flows, dns)
	if got.kind != "discord" || len(got.out) != 3 {
		t.Fatalf("uc paket beklenir: %d", len(got.out))
	}
	head := mustParse(t, got.out[2])
	tail := mustParse(t, got.out[1])
	if head.seq != 1000 || tail.seq != 1002 {
		t.Fatal("parca sirasi bozuk")
	}
	joined := append(append([]byte(nil), head.payload...), tail.payload...)
	if !bytes.Equal(joined, hello) {
		t.Fatal("parcalar merhabayi vermiyor")
	}
	ack := ipv4(protoTCP, []byte{9, 9, 9, 9}, local, tcpSeg(443, 41000, 1, 0x12, nil))
	shrunk := handle(ack, false, flows, dns)
	if len(shrunk.out) != 1 || binary.BigEndian.Uint16(shrunk.out[0][34:36]) != 2 {
		t.Fatal("pencere kuculmedi")
	}
	if len(handle(ack, false, flows, dns).out) != 0 {
		t.Fatal("pencere ikinci kez kuculdu")
	}
}

func put24(b []byte, n int) {
	b[0] = byte(n >> 16)
	b[1] = byte(n >> 8)
	b[2] = byte(n)
}

func clientHello(host string) []byte {
	hb := []byte(host)
	entry := make([]byte, 3+len(hb))
	entry[0] = 0
	binary.BigEndian.PutUint16(entry[1:3], uint16(len(hb)))
	copy(entry[3:], hb)
	list := make([]byte, 2+len(entry))
	binary.BigEndian.PutUint16(list[0:2], uint16(len(entry)))
	copy(list[2:], entry)
	sni := make([]byte, 4+len(list))
	binary.BigEndian.PutUint16(sni[2:4], uint16(len(list)))
	copy(sni[4:], list)
	exts := make([]byte, 2+len(sni))
	binary.BigEndian.PutUint16(exts[0:2], uint16(len(sni)))
	copy(exts[2:], sni)
	tail := append([]byte{0x00, 0x02, 0x00, 0x2f, 0x01, 0x00}, exts...)
	body := make([]byte, 35+len(tail))
	body[0], body[1] = 0x03, 0x03
	for i := 2; i < 34; i++ {
		body[i] = 1
	}
	copy(body[35:], tail)
	hs := make([]byte, 4+len(body))
	hs[0] = 1
	put24(hs[1:], len(body))
	copy(hs[4:], body)
	rec := make([]byte, 5+len(hs))
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func mustParse(t *testing.T, raw []byte) pkt {
	t.Helper()
	p, ok := parse(raw)
	if !ok {
		t.Fatal("paket okunamadi")
	}
	return p
}
