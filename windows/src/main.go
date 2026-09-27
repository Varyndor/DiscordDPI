// DiscordDPI yalnizca Discord'a dokunur. El sikismasini parcalar ve
// Discord adlarinin DNS sorgusunu 77.88.8.8:1253 adresine tasir.
// Baska hicbir trafik degismez.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

const (
	layerNetwork = 0
	protoTCP     = 6
	maxPacket    = 0xFFFF + 40
	fragSize     = 2
	fakeTTL      = 5
	windowSize   = 2
	maxTrack     = 4096

	bitOutbound    = 17
	bitIPChecksum  = 21
	bitTCPChecksum = 22
	bitUDPChecksum = 23
)

// Eslestirme yalnizca tam ad ya da alt alan adidir.
var names = []string{
	"discord.com",
	"discordapp.com",
	"discordapp.net",
	"discord.gg",
	"discord.media",
	"discordcdn.com",
	"discord.dev",
	"discord.new",
	"discord.gift",
	"discord.co",
	"dis.gd",
	"discordstatus.com",
	"discord.store",
	"discordactivities.com",
	"discord-attachments-uploads-prod.storage.googleapis.com",
}

// www.w3.org sunucu adi tasiyan TLS istemci merhabasi. DPI bunu gercek
// el sikisma sayar. Yasam suresi 3 oldugu icin siteye ulasmaz.
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

var (
	mod              *windows.DLL
	procOpen         *windows.Proc
	procRecv         *windows.Proc
	procSend         *windows.Proc
	procShutdown     *windows.Proc
	procClose        *windows.Proc
	procCalcChecksum *windows.Proc

	filt   windows.Handle
	filtMu sync.Mutex
	logMu  sync.Mutex
	logf   *os.File
)

// WinDivert 2.2 ag katmani adresi. Bayraklar Timestamp'ten sonraki
// ilk 4 bayttadir. Giden paketin biti 17'dir; bu deger surucuden olculdu.
type address struct {
	Timestamp int64
	Flags     uint64
	Data      [64]byte
}

func (a *address) outbound() bool { return a.Flags&(1<<bitOutbound) != 0 }

func (a *address) clearChecksumFlags() {
	a.Flags &^= (1 << bitIPChecksum) | (1 << bitTCPChecksum) | (1 << bitUDPChecksum)
}

type pkt struct {
	raw     []byte
	ip4     bool
	tcp     int
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
	var l4 int
	switch raw[0] >> 4 {
	case 4:
		l4 = int(raw[0]&0x0f) * 4
		if l4 < 20 || len(raw) < l4 || (raw[9] != protoTCP && raw[9] != protoUDP) {
			return p, false
		}
		p.ip4 = true
	case 6:
		next := raw[6]
		if next != protoTCP && next != protoUDP {
			return p, false
		}
		l4 = 40
	default:
		return p, false
	}
	p.tcp = l4
	udp := false
	if p.ip4 {
		udp = raw[9] == protoUDP
	} else {
		udp = raw[6] == protoUDP
	}
	p.srcPort = binary.BigEndian.Uint16(raw[l4 : l4+2])
	p.dstPort = binary.BigEndian.Uint16(raw[l4+2 : l4+4])
	if udp {
		if len(raw) < l4+8 {
			return p, false
		}
		p.tcp = l4
		p.data = l4 + 8
		p.payload = raw[p.data:]
		return p, true
	}
	p.seq = binary.BigEndian.Uint32(raw[l4+4 : l4+8])
	off := int(raw[l4+12]>>4) * 4
	if off < 20 || len(raw) < l4+off {
		return p, false
	}
	flags := raw[l4+13]
	p.syn = flags&0x02 != 0
	p.ack = flags&0x10 != 0
	p.data = l4 + off
	p.payload = raw[p.data:]
	return p, true
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

func loadDLL() error {
	var err error
	mod, err = windows.LoadDLL("WinDivert.dll")
	if err != nil {
		return errors.New("WinDivert.dll yok. discorddpi.exe ile ayni klasorde durmali")
	}
	for name, dest := range map[string]**windows.Proc{
		"WinDivertOpen":                &procOpen,
		"WinDivertRecv":                &procRecv,
		"WinDivertSend":                &procSend,
		"WinDivertShutdown":            &procShutdown,
		"WinDivertClose":               &procClose,
		"WinDivertHelperCalcChecksums": &procCalcChecksum,
	} {
		p, e := mod.FindProc(name)
		if e != nil {
			return fmt.Errorf("%s bulunamadi", name)
		}
		*dest = p
	}
	return nil
}

func explain(e error) error {
	var n windows.Errno
	if errors.As(e, &n) {
		switch n {
		case 5:
			return errors.New("erisim engellendi: dosyaya sag tik, yonetici olarak calistir")
		case 2:
			return errors.New("WinDivert64.sys yok. discorddpi.exe ile ayni klasorde durmali")
		case 577:
			return errors.New("surucu imzasi reddedildi")
		case 654:
			return errors.New("eski WinDivert surucusu yuklu. Yonetici terminalde: sc stop WinDivert & sc delete WinDivert")
		case 1275:
			return errors.New("surucu engellendi. Antivirus dislamasina klasoru ekleyin")
		}
	}
	return e
}

func openFilter(filter string) (windows.Handle, error) {
	s, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r, _, e := procOpen.Call(uintptr(unsafe.Pointer(s)), layerNetwork, 0, 0)
	h := windows.Handle(r)
	if h == 0 || h == windows.InvalidHandle {
		return 0, explain(e)
	}
	return h, nil
}

func recvPkt(h windows.Handle, buf []byte, addr *address) (int, error) {
	var n uint32
	r, _, e := procRecv.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return 0, e
	}
	return int(n), nil
}

func sendPkt(h windows.Handle, buf []byte, addr *address) error {
	r, _, e := procSend.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return e
	}
	return nil
}

func fixChecksum(buf []byte, addr *address) {
	addr.clearChecksumFlags()
	procCalcChecksum.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
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
		if ln < 0 || i+ln > extEnd {
			return "", false
		}
		if typ == 0 && ln >= 5 && data[i+2] == 0 {
			n := u16(data[i+3:])
			if n >= 3 && 5+n <= ln {
				name := data[i+5 : i+5+n]
				if hostOK(name) {
					return string(name), true
				}
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

func discordHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range names {
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return false
}

type flowKey struct {
	local [16]byte
	peer  [16]byte
	lp    uint16
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

func (p pkt) udp() bool {
	if p.ip4 {
		return p.raw[9] == protoUDP
	}
	return len(p.raw) > 6 && p.raw[6] == protoUDP
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

func redirectDNS(p pkt, addr address) (dnsFlow, []byte, address, bool) {
	if !p.ip4 || !p.udp() || p.dstPort != 53 {
		return dnsFlow{}, nil, addr, false
	}
	id, ok := discordQuery(p.payload)
	if !ok {
		return dnsFlow{}, nil, addr, false
	}
	buf := append([]byte(nil), p.raw...)
	copy(buf[16:20], dns4)
	binary.BigEndian.PutUint16(buf[p.tcp+2:p.tcp+4], dnsPort)
	a := addr
	fixChecksum(buf, &a)
	return p.dnsOutKey(id), buf, a, true
}

func restoreDNS(p pkt, pend dnsPend, addr address) ([]byte, address) {
	buf := append([]byte(nil), p.raw...)
	copy(buf[12:16], pend.server[:4])
	binary.BigEndian.PutUint16(buf[p.tcp:p.tcp+2], 53)
	a := addr
	fixChecksum(buf, &a)
	return buf, a
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

type tracker struct {
	mu sync.Mutex
	m  map[flowKey]time.Time
}

func (t *tracker) add(k flowKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) > maxTrack {
		cut := time.Now().Add(-2 * time.Minute)
		for key, ts := range t.m {
			if ts.Before(cut) {
				delete(t.m, key)
			}
		}
	}
	t.m[k] = time.Now()
}

func (t *tracker) take(k flowKey) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.m[k]; !ok {
		return false
	}
	delete(t.m, k)
	return true
}

func sendFake(h windows.Handle, p pkt, addr address) {
	n := p.data + len(fakeHello)
	if n > maxPacket {
		return
	}
	buf := make([]byte, n)
	copy(buf, p.raw[:p.data])
	copy(buf[p.data:], fakeHello)
	p.setLen(buf, n)
	p.setTTL(buf, fakeTTL)
	a := addr
	fixChecksum(buf, &a)
	_ = sendPkt(h, buf, &a)
}

func sendSlice(h windows.Handle, p pkt, addr address, from, to, seqAdd int) {
	buf := make([]byte, p.data+(to-from))
	copy(buf, p.raw[:p.data])
	copy(buf[p.data:], p.payload[from:to])
	p.setLen(buf, len(buf))
	if seqAdd != 0 {
		binary.BigEndian.PutUint32(buf[p.tcp+4:p.tcp+8], p.seq+uint32(seqAdd))
	}
	a := addr
	fixChecksum(buf, &a)
	_ = sendPkt(h, buf, &a)
}

// split, gercek merhabayi once kuyruk sonra bas olarak yollar.
// Orijinal paket yollanmaz.
func split(h windows.Handle, p pkt, addr address) {
	if len(p.payload) <= fragSize {
		a := addr
		fixChecksum(p.raw, &a)
		_ = sendPkt(h, p.raw, &a)
		return
	}
	sendSlice(h, p, addr, fragSize, len(p.payload), fragSize)
	sendSlice(h, p, addr, 0, fragSize, 0)
}

func shrinkWindow(p pkt) {
	binary.BigEndian.PutUint16(p.raw[p.tcp+14:p.tcp+16], windowSize)
}

func note(format string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(format, args...) + "\n"
	fmt.Print(line)
	logMu.Lock()
	defer logMu.Unlock()
	if logf != nil {
		_, _ = logf.WriteString(line)
	}
}

func openLog() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	path := filepath.Join(filepath.Dir(exe), "discorddpi.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 200_000 {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err == nil {
		logf = f
	}
}

func setFilt(h windows.Handle) {
	filtMu.Lock()
	filt = h
	filtMu.Unlock()
}

func shutdownFilt() {
	filtMu.Lock()
	h := filt
	filtMu.Unlock()
	if h != 0 && procShutdown != nil {
		procShutdown.Call(uintptr(h), 3)
	}
}

func run(ready chan<- struct{}) error {
	note("DiscordDPI")
	note("Yalnizca Discord el sikismasi ve Discord DNS sorgusu islenir.")
	if err := loadDLL(); err != nil {
		return err
	}
	// Uygulama verisi (0x17) ve 4096 bayttan buyuk paketler cekirdekte kalir.
	filter := "!impostor and (" +
		"(tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0 and tcp.PayloadLength < 4096 and tcp.Payload16[0] == 0x1603)" +
		" or (tcp and tcp.SrcPort == 443 and tcp.Syn and tcp.Ack)" +
		" or (udp and udp.DstPort == 53 and ip and udp.PayloadLength >= 12 and udp.PayloadLength < 512)" +
		" or (udp and udp.SrcPort == 1253 and ip.SrcAddr == 77.88.8.8))"
	h, err := openFilter(filter)
	if err != nil {
		return fmt.Errorf("filtre acilamadi: %w", err)
	}
	setFilt(h)
	defer procClose.Call(uintptr(h))
	close(ready)

	pending := tracker{m: map[flowKey]time.Time{}}
	dnsWait := dnsTracker{m: map[dnsFlow]dnsPend{}}
	note("Calisiyor.")
	buf := make([]byte, maxPacket)
	var hits uint64
	var dnsHits uint64
	for {
		var addr address
		n, err := recvPkt(h, buf, &addr)
		if err != nil {
			break
		}
		raw := buf[:n]
		p, ok := parse(raw)
		if !ok {
			_ = sendPkt(h, raw, &addr)
			continue
		}
		if p.udp() {
			if addr.outbound() && p.dstPort == 53 {
				key, out, a, ok := redirectDNS(p, addr)
				if ok {
					var server [16]byte
					copy(server[:4], p.raw[16:20])
					dnsWait.add(key, dnsPend{id: key.id, server: server, at: time.Now()})
					_ = sendPkt(h, out, &a)
					dnsHits++
					if dnsHits <= 30 || dnsHits%200 == 0 {
						name, _, _ := dnsName(p.payload, 12)
						note("dns: %s", name)
					}
					continue
				}
			}
			if !addr.outbound() && p.srcPort == dnsPort && p.ip4 {
				id, ok := replyID(p.payload)
				if ok {
					if pend, hit := dnsWait.take(p.dnsInKey(id)); hit {
						restored, a := restoreDNS(p, pend, addr)
						_ = sendPkt(h, restored, &a)
						continue
					}
				}
			}
			_ = sendPkt(h, raw, &addr)
			continue
		}
		if addr.outbound() && len(p.payload) > 0 {
			host, ok := clientHelloSNI(p.payload)
			if ok && discordHost(host) {
				pending.add(p.key())
				sendFake(h, p, addr)
				split(h, p, addr)
				hits++
				if hits <= 30 || hits%200 == 0 {
					note("discord: %s", host)
				}
				continue
			}
			_ = sendPkt(h, raw, &addr)
			continue
		}
		if p.syn && p.ack && p.srcPort == 443 && pending.take(p.replyKey()) {
			shrinkWindow(p)
			fixChecksum(raw, &addr)
		}
		_ = sendPkt(h, raw, &addr)
	}
	note("Durdu.")
	return nil
}

type svcHandler struct{}

func (svcHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 5000}
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- run(ready) }()
	select {
	case err := <-errc:
		note("baslamadi: %v", err)
		return false, 1
	case <-ready:
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 5000}
				shutdownFilt()
				<-errc
				return false, 0
			}
		case err := <-errc:
			if err != nil {
				note("hata: %v", err)
				return false, 1
			}
			return false, 0
		}
	}
}

func main() {
	openLog()
	defer func() {
		if logf != nil {
			_ = logf.Close()
		}
	}()
	isService, err := svc.IsWindowsService()
	if err == nil && isService {
		_ = svc.Run("DiscordDPI", svcHandler{})
		return
	}
	ready := make(chan struct{})
	errc := make(chan error, 1)
	go func() { errc <- run(ready) }()
	select {
	case err := <-errc:
		fail(err)
	case <-ready:
	}
	fmt.Println("Kapatmak icin bu pencereyi kapatin veya Ctrl+C.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	shutdownFilt()
	<-errc
}

func fail(err error) {
	fmt.Println(err)
	fmt.Println()
	fmt.Println("Kapatmak icin bir tusa basin.")
	os.Stdin.Read(make([]byte, 1))
	os.Exit(1)
}
