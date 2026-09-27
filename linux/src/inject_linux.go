//go:build linux

package main

import "syscall"

var raw4 int

func openRaw() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 0xD1); err != nil {
		return err
	}
	raw4 = fd
	return nil
}

func inject(pkt []byte) error {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return syscall.EINVAL
	}
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], pkt[16:20])
	return syscall.Sendto(raw4, pkt, 0, &addr)
}
