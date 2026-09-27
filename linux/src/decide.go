package main

import "time"

type flowTracker struct {
	m map[flowKey]time.Time
}

func (t *flowTracker) add(k flowKey) {
	if len(t.m) > 4096 {
		cut := time.Now().Add(-2 * time.Minute)
		for key, ts := range t.m {
			if ts.Before(cut) {
				delete(t.m, key)
			}
		}
	}
	t.m[k] = time.Now()
}

func (t *flowTracker) take(k flowKey) bool {
	if _, ok := t.m[k]; !ok {
		return false
	}
	delete(t.m, k)
	return true
}

type verdict struct {
	out  [][]byte
	kind string
	name string
}

// handle, Discord paketini degistirir. Geri verdigi bos liste paketin
// oldugu gibi yollanacagini soyler.
func handle(raw []byte, outbound bool, flows *flowTracker, dns *dnsTracker) verdict {
	p, ok := parse(raw)
	if !ok {
		return verdict{}
	}
	if p.udp() {
		if outbound && p.dstPort == 53 {
			key, out, ok := redirectDNS(p)
			if !ok {
				return verdict{}
			}
			var server [16]byte
			copy(server[:4], p.raw[16:20])
			dns.add(key, dnsPend{id: key.id, server: server, at: time.Now()})
			name, _, _ := dnsName(p.payload, 12)
			return verdict{out: [][]byte{out}, kind: "dns", name: name}
		}
		if !outbound && p.srcPort == dnsPort && p.ip4 {
			id, ok := replyID(p.payload)
			if !ok {
				return verdict{}
			}
			pend, hit := dns.take(p.dnsInKey(id))
			if !hit {
				return verdict{}
			}
			return verdict{out: [][]byte{restoreDNS(p, pend)}}
		}
		return verdict{}
	}
	if outbound && len(p.payload) > 0 {
		host, ok := clientHelloSNI(p.payload)
		if !ok || !discordHost(host) {
			return verdict{}
		}
		flows.add(p.key())
		fake, ok := fakePacket(p)
		if !ok {
			return verdict{}
		}
		parts := splitHello(p)
		return verdict{out: append([][]byte{fake}, parts...), kind: "discord", name: host}
	}
	if !outbound && p.syn && p.ack && p.srcPort == 443 && flows.take(p.replyKey()) {
		return verdict{out: [][]byte{shrinkWindow(p)}}
	}
	return verdict{}
}
