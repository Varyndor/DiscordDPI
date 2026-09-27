package main

import "strings"

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

func discordHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range names {
		if host == n || strings.HasSuffix(host, "."+n) {
			return true
		}
	}
	return false
}
