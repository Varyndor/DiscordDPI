package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func putSNI(name string) []byte {
	nb := []byte(name)
	// server name extension: type 0, list len, name type 0, name len, name
	body := make([]byte, 2+1+2+len(nb))
	binary.BigEndian.PutUint16(body[0:2], uint16(3+len(nb)))
	body[2] = 0
	binary.BigEndian.PutUint16(body[3:5], uint16(len(nb)))
	copy(body[5:], nb)
	ext := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(body)))
	copy(ext[4:], body)

	rec := make([]byte, 0, 128)
	rec = append(rec, 0x16, 0x03, 0x01, 0x00, 0x00)
	rec = append(rec, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03)
	rec = append(rec, make([]byte, 32)...)
	rec = append(rec, 0)    // session id len
	rec = append(rec, 0, 2) // cipher suites len
	rec = append(rec, 0x13, 0x01)
	rec = append(rec, 1, 0) // compression
	el := make([]byte, 2)
	binary.BigEndian.PutUint16(el, uint16(len(ext)))
	rec = append(rec, el...)
	rec = append(rec, ext...)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(rec)-5))
	hsLen := len(rec) - 9
	rec[6] = byte(hsLen >> 16)
	rec[7] = byte(hsLen >> 8)
	rec[8] = byte(hsLen)
	return rec
}

func TestSNI(t *testing.T) {
	hello := putSNI("gateway.discord.gg")
	got, ok := clientHelloSNI(hello)
	if !ok || got != "gateway.discord.gg" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
	if !discordHost(got) {
		t.Fatal("discord.gg alt alani eslesmedi")
	}
	if discordHost("notdiscord.com") {
		t.Fatal("benzer ad eslesti")
	}
	if discordHost("discord.com.evil.test") {
		t.Fatal("sonek disindaki ad eslesti")
	}
	other := putSNI("www.youtube.com")
	got, ok = clientHelloSNI(other)
	if !ok || discordHost(got) {
		t.Fatal("youtube discord sayildi")
	}
	if _, ok := clientHelloSNI([]byte{1, 2, 3}); ok {
		t.Fatal("cop veri SNI sayildi")
	}
}

func TestFakeHelloIsNotDiscord(t *testing.T) {
	got, ok := clientHelloSNI(fakeHello)
	if !ok || got != "www.w3.org" {
		t.Fatalf("sahte merhaba SNI %q ok=%v", got, ok)
	}
	if discordHost(got) {
		t.Fatal("sahte merhaba discord sayildi")
	}
}

func ipv4TCP(src, dst string, sport, dport uint16, payload []byte, synack bool) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = protoTCP
	copy(ip[12:16], []byte{1, 2, 3, 4})
	copy(ip[16:20], []byte{5, 6, 7, 8})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 5 << 4
	if synack {
		tcp[13] = 0x12
	} else {
		tcp[13] = 0x18
	}
	raw := append(append(ip, tcp...), payload...)
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	_ = src
	_ = dst
	return raw
}

func TestRealGoClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2048)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: "gateway.discord.gg", InsecureSkipVerify: true})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = tlsConn.Handshake()
	var raw []byte
	select {
	case raw = <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("istemci merhabasi gelmedi")
	}
	if len(raw) < 50 || len(raw) > 4096 {
		t.Fatalf("beklenmeyen merhaba boyu: %d", len(raw))
	}
	host, ok := clientHelloSNI(raw)
	if !ok || host != "gateway.discord.gg" || !discordHost(host) {
		t.Fatalf("gercek merhaba okunamadi host=%q ok=%v boyut=%d", host, ok, len(raw))
	}
	_ = io.EOF
}

func TestParseRoundTrip(t *testing.T) {
	body := putSNI("cdn.discordapp.com")
	raw := ipv4TCP("", "", 50000, 443, body, false)
	p, ok := parse(raw)
	if !ok || p.dstPort != 443 || p.srcPort != 50000 || !p.ip4 {
		t.Fatalf("parse basarisiz %+v", p)
	}
	host, ok := clientHelloSNI(p.payload)
	if !ok || host != "cdn.discordapp.com" || !discordHost(host) {
		t.Fatalf("host %q", host)
	}
	syn := ipv4TCP("", "", 443, 50000, nil, true)
	copy(syn[12:16], []byte{5, 6, 7, 8})
	copy(syn[16:20], []byte{1, 2, 3, 4})
	sp, ok := parse(syn)
	if !ok || !sp.syn || !sp.ack || sp.srcPort != 443 {
		t.Fatal("synack okunamadi")
	}
	if sp.replyKey() != p.key() {
		t.Fatalf("gelen anahtar giden anahtarla uyusmadi")
	}
}
