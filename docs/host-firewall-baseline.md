# Host firewall ve port maruziyeti — temel kurallar

Bu belge **host seviyesini** anlatır: makinede hangi servisin hangi
arayüzde dinlediğini. Çevre (perimeter) tarafı için:

- `docs/enterprise-lb-firewall-integration.md` — kurumsal LB/firewall topolojileri
- `docs/ziti-nat-firewall-requirements.md` — OpenZiti NAT/NGFW gereksinimleri

Bu belge onların yerine geçmez; **altlarındaki katmandır**.

## 1. Temel ilke: firewall üçüncü savunma hattıdır

Sıralama önemlidir, çünkü ilk ikisi başarısız olduğunda firewall çoğu
zaman yardıma yetişmez:

1. **Bağlanma adresi (bind address).** Servis yalnızca `127.0.0.1`'i
   dinliyorsa, firewall kuralı yanlış olsa bile dışarıdan erişilemez.
2. **Kimlik doğrulama.** Servis uzaktan erişilebilir olmalıysa, kimlik
   doğrulaması *kendisinde* olmalıdır.
3. **Firewall.** Yalnızca ilk ikisi doğruyken anlamlı bir katmandır.

Firewall'a birinci hat olarak güvenmenin somut başarısızlık biçimleri:

- Host üzerinde çalışan **her süreç** ağ firewall'ını zaten atlar.
- Container runtime'ları (Docker/Podman) kendi `iptables`/`nftables`
  kurallarını enjekte eder ve elle yazılmış kuralları **sessizce
  geçersiz kılabilir**. `-p 5432:5432` yazan bir compose satırı,
  firewall'da 5432 "kapalı" görünse bile portu açabilir.
- Kaynak NAT yapan bir yönlendirici, tüm dış trafiği iç adres gibi
  gösterip IP tabanlı izin listelerini **sessizce etkisiz** kılar
  (ayrıntı: `docs/ziti-nat-firewall-requirements.md`).

Bu yüzden aşağıdaki kural, "firewall nasıl yapılandırılmalı"
sorusunun asıl cevabıdır:

> **Varsayılan: her arka uç servisi `127.0.0.1`'e bağlanır.**
> Dışarıya açılan tek şey, kimlik doğrulaması olan ön kapıdır.

## 2. Hangi port açık olmalı

OpenIDX bir host'unda dışarıya açık olması **beklenen** portlar:

| Port | Servis | Not |
|------|--------|-----|
| 22 | SSH | Anahtar tabanlı, parola kapalı |
| 443 | HTTPS (APISIX/nginx) | Tek genel giriş |
| 1280 | Ziti controller | Yalnızca overlay kullanılıyorsa |
| 3022, 3023 | Ziti router | Yalnızca overlay kullanılıyorsa |

**Asla** tüm arayüzlerde dinlememesi gerekenler:

| Port | Servis | Neden |
|------|--------|-------|
| 2379 / 2380 | etcd | Kimlik doğrulama varsayılan olarak **yok** |
| 5432 / 55432 | PostgreSQL | Veritabanı |
| 6379 / 56379 | Redis | Varsayılan olarak parolasız |
| 7474 / 7687 | Neo4j | Veritabanı |
| 9180 / 9280 | APISIX admin API | Rota yönetimi |
| 9090 / 9098 | APISIX control API | Kimlik doğrulaması yok |

Bu listedeki bir servise uzaktan erişim gerçekten gerekiyorsa: kimlik
doğrulama + TLS **zorunludur**, ve erişim kaynak IP ile daraltılmalıdır.

## 3. Neden etcd özellikle tehlikeli

etcd, APISIX'in yapılandırma deposudur ve **varsayılan kurulumda kimlik
doğrulaması yoktur**. `0.0.0.0:2379` dinleyen bir etcd'ye ağdan erişebilen
biri şunu yapabilir:

```
POST /v3/kv/put   → rota/upstream ekle
```

Bu, APISIX admin API'sinin kimlik doğrulamasını **tamamen baypas eder**:
saldırgan admin API'ye hiç dokunmadan trafiği kendi sunucusuna yönlendirebilir.
Yani admin API'yi 401 ile korumak, etcd açıkken **hiçbir şey ifade etmez**.

Aynı mantık Redis için de geçerlidir: OpenIDX oturum ve rate-limit
verisini Redis'te tutar. Parolasız bir Redis, oturum verisini okumaya ve
yazmaya izin verir.

> Not: `docs/SECURITY-HARDENING.md` içindeki Redis maddesi
> "the wire is TLS-protected" varsayımıyla `REQUIREPASS`'i isteğe bağlı
> bırakıyordu. Bu varsayım, Redis loopback dışına bağlandığı anda
> geçersizdir. Parola + loopback bind ikisi birden gerekir.

## 4. Doğru bağlama biçimleri

```yaml
# Docker / Podman — host portunu loopback'e sabitle
ports:
  - "127.0.0.1:56379:6379"     # DOĞRU
  # - "56379:6379"             # YANLIŞ: 0.0.0.0'a açar
```

```yaml
# etcd
command:
  - --listen-client-urls=http://127.0.0.1:2379
  - --advertise-client-urls=http://127.0.0.1:2379
```

```conf
# PostgreSQL (postgresql.conf)
listen_addresses = 'localhost'
```

```conf
# Redis (redis.conf)
bind 127.0.0.1
requirepass <güçlü-parola>
```

`network_mode: host` kullanan container'larda port yayınlama yoktur;
bağlama adresi **uygulamanın kendi yapılandırmasından** gelir. Bu durumda
compose'daki `ports:` satırına bakmak yanıltıcıdır, servisin config'ine
bakılmalıdır.

## 5. Denetim

```bash
scripts/audit-listening-ports.sh            # rapor
scripts/audit-listening-ports.sh --probe    # + kimlik doğrulama yoklaması
ALLOW_PUBLIC="22 443" scripts/audit-listening-ports.sh
```

Betik, tüm arayüzlerde dinleyen ve izin listesinde olmayan her portu
listeler; bilinen arka uç servislerini **KRİTİK** olarak işaretler.
İzin listesi dışında port varsa çıkış kodu `1`'dir, böylece CI veya cron
içinde kullanılabilir.

`--probe` yalnızca okuma yapar (`GET /`), hiçbir şey yazmaz. HTTP 200
dönmesi tek başına "kimlik doğrulama yok" demek **değildir**; giriş
sayfası da 200 döner. Bu yüzden çıktısı bir başlangıç noktasıdır,
kanıt değildir — servisin ayrıcalıklı uç noktası ayrıca denenmelidir.

## 6. Kubernetes'te karşılığı

Hedef dağıtım Kubernetes olduğunda aynı ilke şuna dönüşür:

- Arka uç servisleri `ClusterIP` olur (`NodePort`/`LoadBalancer` **değil**).
  `ClusterIP`, host bind'inin küme içindeki karşılığıdır.
- Varsayılan **deny-all** `NetworkPolicy` yazılır, sonra yalnızca gereken
  yönler açılır. Politika yoksa küme içi trafik tamamen serbesttir; bu,
  `0.0.0.0`'a bağlanmakla aynı sonucu verir.
- etcd/Redis/PostgreSQL için kimlik doğrulama yine **zorunludur**:
  `NetworkPolicy` tek başına yeterli değildir, çünkü aynı namespace'teki
  ele geçirilmiş bir pod politikanın izin verdiği yoldan geçer.
- Ingress tek giriş noktasıdır; admin API'ler Ingress'e **hiç** bağlanmaz.

## 7. Host firewall (üçüncü katman)

Yukarıdaki iki katman doğruysa, host firewall'ı savunmayı derinleştirir.
`nftables` ile asgari bir taban:

```bash
# Yalnızca örnek. Uygulamadan önce SSH erişimini kaybetmeyeceğinizi doğrulayın.
nft add table inet filter
nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
nft add rule inet filter input ct state established,related accept
nft add rule inet filter input iif lo accept
nft add rule inet filter input tcp dport { 22, 443 } accept
```

Uyarılar:

- Kuralları uygulamadan önce **ikinci bir erişim yolu** (konsol/IPMI)
  hazır olmalıdır. `policy drop` yanlış sırada uygulanırsa SSH kopar.
- Docker/Podman kendi zincirlerini yönetir; `FORWARD` zinciri ve
  container NAT kuralları bu tablodan bağımsız çalışabilir. Kural
  yazdıktan sonra `scripts/audit-listening-ports.sh` ile **sonucu
  ölçün**, kuralın metnine güvenmeyin.
- Kural setini kalıcı hale getirmeyi unutmayın; aksi halde yeniden
  başlatmada sessizce kaybolur.
