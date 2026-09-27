# DiscordDPI

Türkiye'de yalnızca Discord için çalışır. El sıkışmasını parçalar ve Discord adlarının DNS sorgusunu çözer. Başka hiçbir trafik değişmez. VPN değildir.

Aynı işi yapan iki program vardır. Birini kurmak diğerini etkilemez. `windows` klasörü 64 bit Windows içindir, `linux` klasörü 64 bit Linux içindir. macOS yoktur: paketlere dokunan bir program, Apple'ın onayladığı bir geliştirici hesabıyla imzalanmadan macOS'ta yüklenemez.

İki programın kendi kodu MIT lisansındadır, `LICENSE` dosyasına bakın.

## Windows

64 bit Windows yeter. Go, .NET veya başka bir program kurulmaz. `windows` klasöründeki `discorddpi.exe`, `WinDivert.dll` ve `WinDivert64.sys` çalışması için yeter.

`windows` klasöründeki `kur.cmd` dosyasına sağ tık, **Yönetici olarak çalıştır**. DiscordDPI hizmeti Windows açılışında kendiliğinden başlar.

`windows` klasöründeki `kaldir.cmd` DiscordDPI hizmetini siler.

Tek seferlik denemek için `windows` klasöründeki `discorddpi.exe` dosyasını yönetici olarak çalıştırın. Pencere kapanınca durur.

Programa yalnızca TLS kaydı `16 03` ile başlayan ve 4096 bayttan kısa giden paket girer. Sunucu adı Discord'a aitse öne, sunucu adı `www.w3.org` olan ve yaşam süresi 5 olan sahte bir merhaba koyar. Gerçek merhaba iki parça gider: önce 2 bayttan sonraki kuyruk, ardından ilk 2 bayt. DPI sunucu adını tek pakette göremez.

Paket yakalama sürücüsü WinDivert 2.2, basil00'ın projesidir: https://github.com/basil00/WinDivert. Lisansı LGPL 3.0, metin `windows/LICENSE-windivert.txt` içindedir.

Yeniden derlemek için Go gerekir:

```
cd windows/src
go build -ldflags "-s -w" -o ../discorddpi.exe .
```

## Linux

64 bit Linux yeter. Intel ve AMD için `linux/discorddpi`, ARM64 için `linux/discorddpi-arm64` vardır. Go kurulmaz.

nftables kurulu olmalıdır. Çoğu dağıtımda hazırdır. Yoksa Ubuntu ve Debian'da `apt install nftables`, Fedora'da `dnf install nftables`.

```
cd linux
sudo ./baslat.sh
```

Durdurmak için `Ctrl+C`. Program kapanınca kuralı da siler. Kural takılı kalırsa:

```
cd linux
sudo ./durdur.sh
```

nftables, programa yalnızca şunları verir: 512 bayttan kısa IPv4 UDP DNS sorguları, 443 portuna giden bağlantının ilk veri paketleri, `77.88.8.8:1253` adresinden gelen cevaplar ve 443 portundan gelen SYN+ACK. Geri kalan trafik çekirdekte kalır.

Sahte merhaba ve kuyruk ham soketten `0xD1` işaretiyle çıkar; bu işaret kurala tekrar girmez. İlk 2 bayt, yakalanan paketin yerine konur.

Yeniden derlemek için Go gerekir:

```
cd linux/src
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o ../discorddpi .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o ../discorddpi-arm64 .
```

## İki programda ortak olan

Discord adına ait tek soruluk IPv4 UDP sorgusu 512 bayttan kısaysa Yandex DNS sunucusu `77.88.8.8` adresinin 1253 portuna gider. Cevap geldiğinde, sorguyu gönderen DNS sunucusundan gelmiş gibi geri yazılır. Bu adrese yalnızca Discord adları gider. IPv6 sorguları, TCP üzerinden DNS ve 512 bayt ile daha uzun UDP sorguları akışta kalır. `example.com` gibi diğer adlar, UDP'nin geri kalanı, QUIC ve 443 dışındaki portlar akışta kalır.

Eşleşen adlar: discord.com, discordapp.com, discordapp.net, discord.gg, discord.media, discordcdn.com, discord.dev, discord.new, discord.gift, discord.co, dis.gd, discordstatus.com, discord.store, discordactivities.com, discord-attachments-uploads-prod.storage.googleapis.com. Alt alan adları da sayılır.
