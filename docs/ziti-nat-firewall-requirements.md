# OpenZiti — NAT ve Firewall Gereksinimleri (Palo Alto dahil)

> **Kime:** ağ/güvenlik ekipleri.
> **Soru:** OpenIDX'in Ziti overlay'ini internete açarken NAT'ta ve firewall'da
> ne gerekiyor? Kaynak NAT gerekli mi? Palo Alto'da SSL decryption açık kalabilir mi?

**Tek cümlelik cevap:** Yalnızca **hedef NAT (destination NAT / port forward)**
gerekir; **kaynak NAT (SNAT/masquerade) kullanmayın** ve bu trafiği Palo Alto'da
**SSL decryption'dan muaf tutun** — aksi hâlde overlay hiç kurulmaz.

Bu belgedeki her port ve davranış bu kurulumda **ölçülerek** doğrulanmıştır;
"varsayılan şudur" denilerek yazılmamıştır. Doğrulama komutları bölüm 7'de.

---

## 1. Hangi portlar, hangi yön

Ziti'de yön çok önemli: **istemciler hiçbir inbound port açmaz.** Inbound yalnızca
**public rolü olan** bileşenler için gerekir. Bu kurulumda denetleyici ve router
public rolündedir.

| Bileşen | Port | Yön | Bu kurulumda gerekli mi | Ne için |
|---|---|---|---|---|
| Denetleyici (controller) | **1280/TCP** | inbound | **Evet** | İstemci kaydı, kimlik doğrulama, yönetim API'si |
| Edge router | **3022/TCP** | inbound | **Evet** | Veri düzlemi (native istemciler) |
| Edge router (wss) | **3023/TCP** | inbound | **Evet — BrowZer kullanılıyorsa** | Tarayıcı (clientless) veri düzlemi |
| Edge (BrowZer web) | **443/TCP** | inbound | **Evet** | BrowZer bootstrap + uygulama arayüzü |
| İstemciler (ZDE/ZME/tunneler) | — | inbound | **Hayır** | İstemci yalnızca outbound bağlanır |

**Neden bu portlar:** denetleyicinin istemcilere dağıttığı router adresleri
ölçüldü ve doğrudan bunlar çıktı:

```
supportedProtocols: {"tls": "tls://browzer.tdv.org:3022",
                     "wss": "wss://browzer.tdv.org:3023"}
```

Yani istemci, denetleyiciye bağlandıktan sonra **tam olarak bu adreslere**
gidecektir. Port forward listesi tahminle değil, bu listeden çıkar.

### İstemci tarafında (şube/kullanıcı ağı) ne gerekir

Yalnızca **outbound** izin: `1280/TCP`, `3022/TCP` (+ tarayıcı için `3023/TCP`
ve `443/TCP`). Kullanıcı ağında **hiçbir inbound kural gerekmez** — Ziti'nin
ana faydalarından biri budur.

---

## 2. NAT: yalnızca hedef NAT, kaynak NAT **hayır**

Router'da yapılacak yönlendirme:

```
<PUBLIC_IP>:1280 → <ZITI_HOST>:1280    (denetleyici)
<PUBLIC_IP>:3022 → <ZITI_HOST>:3022    (router, native)
<PUBLIC_IP>:3023 → <ZITI_HOST>:3023    (router, BrowZer/wss)
<PUBLIC_IP>:443  → <EDGE_HOST>:443     (BrowZer web / uygulama edge)
```

Bu, çoğu üründe "Port Forwarding" / "Virtual Server" / "Destination NAT" adıyla
geçer. **"Masquerade", "full cone", "hairpin/NAT loopback", "source NAT"
seçeneklerini açmayın.**

### Kaynak NAT neden zararlı

Kaynak NAT açılırsa dışarıdan gelen her istek, hedefe **router'ın kendi iç
IP'siyle** ulaşır. Sonuçları:

1. **IP tabanlı kısıtlar sessizce ölür.** Bu kurulumda somut olarak yaşandı:
   Ziti yönetim API'si (`/edge/management/v1`) iç ağlarla sınırlanmıştı, ancak
   izin listesi router'ın LAN IP'sini de kapsıyordu. SNAT açık olsaydı dış
   istekler izinli görünecek, kısıt **var görünüp hiçbir şeyi engellemeyecekti**.
   Bu yüzden izin listesi gateway'i **dışlayacak** şekilde yeniden yazıldı
   (bkz. `deployments/apisix-edge/seed-edge-routes.sh`).
2. **Denetim (audit) körleşir.** OpenIDX'te `actor_ip` alanı **69 yerde**
   kullanılıyor. SNAT altında tüm kayıtlar tek bir IP'ye düşer; "kim nereden
   bağlandı" sorusu cevapsız kalır.
3. **IP tabanlı hız sınırlama anlamını yitirir.** Tüm dış trafik tek kaynağa
   toplandığı için ya herkes engellenir ya da kimse.
4. **Ziti'nin kendi görünürlüğü bozulur.** Denetleyici tüm istemcileri aynı
   adresten görür.

**Güvenli tasarım notu:** izin listesi gateway'i dışladığı için, yanlışlıkla SNAT
açılırsa dış istekler **reddedilir**. Yani hatalı yapılandırma sessiz bir açık
değil, **görünür bir arıza** üretir.

### NAT açıldıktan sonra ilk doğrulama

Edge log'unda ilk isteğin kaynak IP'sine bakın:

- **Public bir IP görüyorsanız:** doğru, yalnızca hedef NAT yapılıyor.
- **Router'ın iç IP'sini görüyorsanız:** SNAT açık, kapatın.

---

## 3. Palo Alto (ve diğer NGFW) — kritik nokta

### SSL decryption bu trafiğe **uygulanmamalı**

NetFoundry'nin resmî firewall dokümanı bunu açıkça söylüyor:

> "Outbound traffic going toward the Controller and Hosted Fabric should be
> excluded from any Proxy and/or Web Application firewall. **Deep packet
> Inspection will cause reachability issues** to the controller and other ERs."

Bunun teknik sebebi bu kurulumda ölçüldü:

| Uç nokta | Ölçülen davranış | SSL decryption'a tepkisi |
|---|---|---|
| Denetleyici `:1280` | **mTLS** — sunucu istemci sertifikası **istiyor**, ALPN `ziti-ctrl` | **Kırılır.** Araya giren firewall istemcinin özel anahtarına sahip olmadığı için istemci sertifikasını sunamaz |
| Router `:3022` | Sertifika **NetFoundry iç PKI**'sinden (`CN=NetFoundry Inc. Intermediate CA`), ALPN `ziti-edge` | **Kırılır.** İstemci bu sertifikayı Ziti'nin kendi CA'sına göre doğrular; firewall'ın ürettiği sertifika **kasten** reddedilir |
| Router `:3023` (wss) | Sertifika **public CA** (GlobalSign), ALPN `http/1.1` | Bootstrap TLS'i teknik olarak açılabilir, ama **içindeki Ziti oturumu yine uçtan uca şifrelidir** — açmanın hiçbir görünürlük faydası yok, sadece risk ve gecikme ekler |

Yani Ziti'nin sertifika sabitleme (pinning) davranışı bir kusur değil,
**tasarımın kendisidir**: araya girme girişimi başarısız olmalıdır.

### Palo Alto'da yapılacak yapılandırma

1. **Decryption policy — no-decrypt kuralı** (en üste, decrypt kurallarından önce):
   - Kaynak: istemci ağları
   - Hedef: denetleyici ve router public adresleri
   - Servis: `1280/TCP`, `3022/TCP`, `3023/TCP`
   - Eylem: **No Decrypt**

2. **App-ID:** Ziti trafiği standart bir App-ID'ye oturmaz; büyük ihtimalle
   `ssl` ya da `unknown-tcp` görünür. Güvenlik kuralını **application yerine
   service/port** üzerinden yazın; `application-default` kullanmayın, aksi hâlde
   trafik sessizce düşer.

3. **Threat Prevention / IPS:** bu kurallarda **kapalı** tutun. Trafik zaten
   uçtan uca şifreli olduğu için tarama hiçbir şey göremez, yalnızca
   yanlış-pozitif ve gecikme üretir.

4. **Session timeout:** Ziti kontrol kanalı uzun ömürlü ve sessiz kalabilir.
   Firewall'ın TCP idle timeout değeri Ziti'nin kendi idle aralığından **kısa
   olmamalıdır**; kısa olursa oturumlar sessizce düşer ve istemciler periyodik
   olarak yeniden bağlanır.

   Bu kurulumda ölçülen değerler: router websocket `idleTimeout: 120` (saniye),
   denetleyici Edge API `sessionTimeout: 30m`, heartbeat kalıcılaştırma
   varsayılanı `90s`. Buna göre firewall idle timeout'u **en az 120 saniye**
   olmalı; güvenli seçim 30 dakikanın üzerinde bırakmaktır. Palo Alto'nun `tcp`
   varsayılanı 3600 sn olduğu için bu kurulumda sorun **yok**; sıkılaştırılmış
   profillerde (ör. 120 sn altı) bu kontrol edilmelidir.

   > Bu değer ilk yazımda yanlışlıkla "65 sn" olarak geçmişti; o değer
   > `initialLinkLatency`, yani router-to-router link gecikmesinin başlangıç
   > tahminidir, idle/heartbeat ile ilgisi yoktur. Config okunarak düzeltildi.

5. **Asimetrik yol / SYN kontrolü:** port forward ile birlikte kaynak NAT
   yapılmadığı için dönüş trafiğinin aynı firewall üzerinden geçtiğinden emin
   olun. Değilse `tcp-reject-non-syn no` gerekebilir — ama doğru çözüm
   yönlendirmeyi düzeltmektir.

---

## 4. Tek portla çalışmak (ALPN)

NetFoundry dokümanına göre yeni sürümler ALPN sayesinde ayrı `80/TCP`
gereksinimini kaldırmıştır ve tek `443` üzerinden çalışılabilir. Bu kurulumda
ALPN'in **aktif olduğu ölçüldü** (`ziti-ctrl`, `ziti-edge`).

Kısıtlı ağlarda (yalnız 443'e izin veren misafir/otel ağları) router'ı 443'ten
yayınlamak mümkündür; ancak bu kurulumda 443 zaten APISIX edge tarafından
kullanılıyor. Bu bir çakışmadır ve ayrı bir IP ya da ayrı bir host gerektirir —
**bu belge yazılırken uygulanmadı**, gerekirse ayrıca planlanmalıdır.

---

## 5. Bu kurulumda tespit edilen iki yapılandırma notu

Ölçüm sırasında çıkan, güvenlik açığı olmayan ama düzeltilmesi gereken iki nokta:

1. **Kullanılmayan link listener.** Router'da `link.listeners` tanımlı ve
   `3022`'yi advertise ediyor. Link listener yalnızca **router-to-router** fabric
   bağlantıları için anlamlıdır; bu kurulumda **tek router** var ve log'larda
   hiçbir link etkinliği görülmedi (son 400 satırda 0 kayıt). Zararsız, ancak
   ikinci bir router eklenene kadar gereksiz bir yayınlanmış yetenektir.

2. **Denetleyici ve router aynı host'ta, `network_mode: host`.** Bu, port
   forward'ı basitleştirir ama HA açısından tek arıza noktasıdır. Router'ın
   ayrı bir host'a taşınması, denetleyici internete açılmadan önce
   değerlendirilmelidir.

---

## 6. Özet — router/firewall ekibine verilecek liste

```
HEDEF NAT (destination NAT / port forward) — kaynak NAT YOK:
  <PUBLIC_IP>:1280  → <ZITI_HOST>:1280     TCP   denetleyici
  <PUBLIC_IP>:3022  → <ZITI_HOST>:3022     TCP   router (native veri düzlemi)
  <PUBLIC_IP>:3023  → <ZITI_HOST>:3023     TCP   router (BrowZer/wss)
  <PUBLIC_IP>:443   → <EDGE_HOST>:443      TCP   BrowZer web / uygulama edge

KAPALI KALACAK:
  masquerade / source NAT / full cone / hairpin (NAT loopback)

PALO ALTO:
  Decryption policy  : bu 3 port için NO DECRYPT (en üstte)
  Güvenlik kuralı    : service/port bazlı, application-default DEĞİL
  Threat prevention  : bu kurallarda kapalı
  TCP idle timeout   : >= 120 sn (router idleTimeout); tercihen > 30 dk

İSTEMCİ AĞLARI:
  Yalnızca outbound 1280, 3022 (+3023, 443). Inbound kural GEREKMEZ.
```

---

## 7. Doğrulama komutları

Aşağıdakiler bu belgedeki iddiaları üreten komutlardır; kendi ortamınızda
tekrar çalıştırılabilir.

```bash
# İstemcilere hangi router adresleri dağıtılıyor (port forward listesi buradan çıkar)
ziti edge list edge-routers -j | jq '.data[].supportedProtocols'

# Denetleyici mTLS istiyor mu? (çıktıda "Acceptable client certificate CA names" olmalı)
openssl s_client -connect <ZITI_HOST>:1280 -servername <CTRL_FQDN> </dev/null 2>&1 \
  | grep -i 'Acceptable client certificate'

# ALPN ne ilan ediliyor
openssl s_client -connect <ZITI_HOST>:1280 -alpn ziti-ctrl </dev/null 2>&1 | grep ALPN
openssl s_client -connect <ZITI_HOST>:3022 -alpn ziti-edge </dev/null 2>&1 | grep ALPN

# Router hangi CA'dan sertifika sunuyor (SSL decryption'ın neden kırılacağı)
openssl s_client -connect <ZITI_HOST>:3022 </dev/null 2>&1 | grep -E '^ *[01] [si]:'

# NAT açıldıktan sonra: gelen isteğin kaynak IP'si public mi?
docker logs <EDGE_CONTAINER> 2>&1 | tail -20
```

---

## Ek: kaynaklar

- NetFoundry, *Firewall Requirements* — DPI'ın erişilebilirliği bozduğu ve
  outbound trafiğin proxy/WAF'tan muaf tutulması gerektiği; ALPN ile tek port.
- OpenZiti *Router / Controller configuration reference* — `link.listeners`,
  `bindPoints`, `advertise` alanlarının anlamı.
- Bu kurulumda yapılan ölçümler (bölüm 7'deki komutlar).
