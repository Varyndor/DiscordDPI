package main

import (
	"encoding/binary"
	"testing"
)

func dnsQuery(name string, flags uint16, questions uint16) []byte {
	b := []byte{
		0x12, 0x34,
		byte(flags >> 8), byte(flags),
		byte(questions >> 8), byte(questions),
		0, 0, 0, 0, 0, 0,
	}
	for _, label := range splitDots(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0, 0, 1, 0, 1)
	return b
}

func splitDots(name string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, name[start:i])
			start = i + 1
		}
	}
	return out
}

func ipv4UDP(src, dst []byte, sport, dport uint16, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[8] = 64
	ip[9] = protoUDP
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(udp[8:], payload)
	raw := append(ip, udp...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	return raw
}

func TestDNSKeysMatch(t *testing.T) {
	q := dnsQuery("updates.discord.com", 0x0100, 1)
	out, ok := parse(ipv4UDP([]byte{192, 168, 1, 3}, []byte{192, 168, 1, 1}, 53000, 53, q))
	if !ok || !out.udp() || out.dstPort != 53 {
		t.Fatal("giden dns okunamadi")
	}
	replyPayload := dnsQuery("updates.discord.com", 0x8180, 1)
	in, ok := parse(ipv4UDP(dns4, []byte{192, 168, 1, 3}, dnsPort, 53000, replyPayload))
	rid, ok := replyID(replyPayload)
	if !ok || in.dnsInKey(rid) != out.dnsOutKey(rid) {
		t.Fatal("cevap anahtari sorguyla uyusmadi")
	}
	id, ok := discordQuery(out.payload)
	if !ok || id != 0x1234 {
		t.Fatal("paketteki soru okunamadi")
	}
}

func TestDiscordQuery(t *testing.T) {
	id, ok := discordQuery(dnsQuery("updates.discord.com", 0x0100, 1))
	if !ok || id != 0x1234 {
		t.Fatalf("updates sorusu okunamadi id=%x ok=%v", id, ok)
	}
	if _, ok := discordQuery(dnsQuery("example.com", 0x0100, 1)); ok {
		t.Fatal("example.com discord sayildi")
	}
	if _, ok := discordQuery(dnsQuery("discord.com.evil.test", 0x0100, 1)); ok {
		t.Fatal("benzer ad discord sayildi")
	}
	if _, ok := discordQuery(dnsQuery("updates.discord.com", 0x8180, 1)); ok {
		t.Fatal("dns cevabi soru sayildi")
	}
	if _, ok := discordQuery(dnsQuery("updates.discord.com", 0x0100, 2)); ok {
		t.Fatal("coklu soru yonlendirildi")
	}
	resp := dnsQuery("updates.discord.com", 0x8180, 1)
	got, ok := replyID(resp)
	if !ok || got != 0x1234 {
		t.Fatalf("cevap kimligi %x ok=%v", got, ok)
	}
	if _, ok := replyID(dnsQuery("updates.discord.com", 0x0100, 1)); ok {
		t.Fatal("soru cevap sayildi")
	}
}
