# DiscordDPI

Türkiye'de Discord'un açılması için çalışan bir programdır. Sağlayıcı, TLS el sıkışmasının ilk paketindeki sunucu adını görünce bağlantıyı keser. Discord adları da sıradan DNS sorgusuyla çözülmez. DiscordDPI bu iki noktaya dokunur. Başka hiçbir trafik değişmez. VPN değildir; paketler başka bir sunucudan geçmez.

Aynı işi yapan iki program vardır. Birini kurmak diğerini etkilemez. `windows` klasörü 64 bit Windows içindir, `linux` klasörü 64 bit Linux içindir.

İki programın kendi kodu MIT lisansındadır, `LICENSE` dosyasına bakın.

## Ne yapar

Bir TLS bağlantısı dört adımda kurulur: istemci SYN gönderir, sunucu SYN+ACK ile cevap verir, istemci ACK yollar, ardından istemci merhabası gider. Sunucu adı bu son paketin içindedir. DiscordDPI bu paketi okur.

Programa yalnızca TLS kaydı `16 03` ile başlayan ve 4096 bayttan kısa giden paket girer. Sunucu adı Discord değilse paket olduğu gibi çıkar.

Sunucu adı Discord'a aitse aynı paketten üç paket üretilir:

1. Sunucu adı `www.w3.org` olan sahte bir istemci merhabası. Yaşam süresi 5'tir. Denetim noktasına varır, asıl siteye varmadan düşer.
2. Gerçek merhabanın ilk 2 baytından sonraki kuyruğu. TCP sıra numarası 2 artırılır.
3. Gerçek merhabanın ilk 2 baytı. TCP sıra numarası değişmez.

Discord sunucusu sıra numarasına göre birleştirir ve merhabayı tam görür. Denetim noktası paketleri varış sırasıyla görür; sunucu adı tek bir pakette durmadığı için bağlantı kesilmez. Orijinal paket yollanmaz. Her parçanın IP ve TCP toplamı yeniden hesaplanır.

## DNS

Discord adına ait tek soruluk IPv4 UDP sorgusu 512 bayttan kısaysa Yandex DNS sunucusu `77.88.8.8` adresinin 1253 portuna gider. Cevap geldiğinde, sorguyu gönderen DNS sunucusundan ve 53 portundan gelmiş gibi geri yazılır. Eşleşme yerel adres, yerel port ve soru kimliğiyle yapılır; aynı anda gelen ikinci soru birincinin cevabını düşürmez. Bu adrese yalnızca Discord adları gider.

IPv6 sorguları, TCP üzerinden DNS ve 512 bayt ile daha uzun UDP sorguları akışta kalır. `example.com` gibi diğer adlar, UDP'nin geri kalanı, QUIC ve 443 dışındaki portlar akışta kalır.

Eşleşen adlar: discord.com, discordapp.com, discordapp.net, discord.gg, discord.media, discordcdn.com, discord.dev, discord.new, discord.gift, discord.co, dis.gd, discordstatus.com, discord.store, discordactivities.com, discord-attachments-uploads-prod.storage.googleapis.com. Alt alan adları da sayılır.

## Windows

64 bit Windows yeter. Go, .NET veya başka bir program kurulmaz. `windows` klasöründeki `discorddpi.exe`, `WinDivert.dll` ve `WinDivert64.sys` çalışması için yeter.

`windows` klasöründeki `kur.cmd` dosyasına sağ tık, **Yönetici olarak çalıştır**. DiscordDPI hizmeti Windows açılışında kendiliğinden başlar.

`windows` klasöründeki `kaldir.cmd` DiscordDPI hizmetini siler.

Tek seferlik denemek için `windows` klasöründeki `discorddpi.exe` dosyasını yönetici olarak çalıştırın. Pencere kapanınca durur.

Paketleri WinDivert 2.2 yakalar. Bu sürücü basil00'ın projesidir: https://github.com/basil00/WinDivert. Lisansı LGPL 3.0, metin `windows/LICENSE-windivert.txt` içindedir. Değişen paket aynı yöne geri verilir.

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

Durdurmak için `Ctrl+C`. Program kapanınca nftables kuralını da siler. Kural takılı kalırsa:

```
cd linux
sudo ./durdur.sh
```

nftables, programa yalnızca şunları verir: 512 bayttan kısa IPv4 UDP DNS sorguları, 443 portuna giden bağlantının ilk veri paketleri, `77.88.8.8:1253` adresinden gelen cevaplar ve 443 portundan gelen SYN+ACK. Geri kalan trafik çekirdekte kalır.

Sahte merhaba ve kuyruk ham soketten `0xD1` işaretiyle çıkar. nftables bu işareti görünce paketi yeniden kuyruğa koymaz. İlk 2 bayt, yakalanan paketin yerine konur.

Yeniden derlemek için Go gerekir:

```
cd linux/src
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o ../discorddpi .
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o ../discorddpi-arm64 .
```
