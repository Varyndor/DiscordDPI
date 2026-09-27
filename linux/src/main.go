//go:build linux

// DiscordDPI Linux'ta yalnizca Discord'a dokunur. El sikismasini parcalar
// ve Discord adlarinin DNS sorgusunu 77.88.8.8:1253 adresine tasir.
// Baska hicbir trafik degismez.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue"
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("yonetici olarak calistirin: sudo ./discorddpi")
		os.Exit(1)
	}
	fmt.Println("DiscordDPI")
	fmt.Println("Yalnizca Discord el sikismasi ve Discord DNS sorgusu islenir.")
	if err := installRules(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer removeRules()

	cfg := nfqueue.Config{
		NfQueue:      1,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 50 * time.Millisecond,
	}
	nf, err := nfqueue.Open(&cfg)
	if err != nil {
		fmt.Println("kuyruk acilamadi:", err)
		os.Exit(1)
	}
	defer nf.Close()
	if err := openRaw(); err != nil {
		fmt.Println("ham soket acilamadi:", err)
		os.Exit(1)
	}

	flows := &flowTracker{m: map[flowKey]time.Time{}}
	dnsWait := &dnsTracker{m: map[dnsFlow]dnsPend{}}
	var hits, dnsHits uint64
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			return 0
		}
		id := *a.PacketID
		raw := *a.Payload
		v := handle(raw, outbound(a), flows, dnsWait)
		if len(v.out) == 0 {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		if len(v.out) == 1 {
			_ = nf.SetVerdictModPacket(id, nfqueue.NfAccept, v.out[0])
		} else {
			sent := true
			for _, extra := range v.out[:len(v.out)-1] {
				if err := inject(extra); err != nil {
					sent = false
					fmt.Println("paket gonderilemedi:", err)
					break
				}
			}
			if !sent {
				_ = nf.SetVerdict(id, nfqueue.NfAccept)
				return 0
			}
			_ = nf.SetVerdictModPacket(id, nfqueue.NfAccept, v.out[len(v.out)-1])
		}
		switch v.kind {
		case "dns":
			dnsHits++
			if dnsHits <= 30 || dnsHits%200 == 0 {
				fmt.Printf("%s dns: %s\n", time.Now().Format("15:04:05"), v.name)
			}
		case "discord":
			hits++
			if hits <= 30 || hits%200 == 0 {
				fmt.Printf("%s discord: %s\n", time.Now().Format("15:04:05"), v.name)
			}
		}
		return 0
	}, func(e error) int {
		if errors.Is(e, syscall.ENOBUFS) {
			return 0
		}
		fmt.Println("kuyruk:", e)
		return 0
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Calisiyor. Durdurmak icin Ctrl+C.")
	<-ctx.Done()
	fmt.Println("Durdu.")
}

func outbound(a nfqueue.Attribute) bool {
	return a.Hook != nil && *a.Hook == 3
}

func installRules() error {
	removeRules()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewReader([]byte(rules()))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables kurali yazilamadi: %v %s", err, out)
	}
	return nil
}

func removeRules() {
	_ = exec.Command("nft", "delete", "table", "inet", tableName).Run()
}


