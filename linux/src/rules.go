package main

import "strings"

const tableName = "discorddpi"

// rules, yalnizca Discord'un DNS sorgusu ile el sikismasini programa verir.
// Diger trafik cekirdekte kalir.
func rules() string {
	return strings.TrimSpace(`
table inet discorddpi {
	chain output {
		type filter hook output priority -160; policy accept;
		meta mark 0xD1 accept
		meta l4proto udp udp dport 53 ip length >= 40 ip length < 540 queue num 1 bypass
		tcp dport 443 tcp flags & (fin | rst | syn) == 0 ct packets 1-12 queue num 1 bypass
	}
	chain input {
		type filter hook input priority -160; policy accept;
		meta l4proto udp udp sport 1253 ip saddr 77.88.8.8 queue num 1 bypass
		tcp sport 443 tcp flags & (syn | ack) == syn | ack ct packets 1-4 queue num 1 bypass
	}
}
`) + "\n"
}
