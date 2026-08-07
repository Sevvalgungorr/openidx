# Kurumsal Yük Dengeleyici & Firewall ile OpenIDX Entegrasyonu

> **Kime:** ağ/güvenlik ekipleri ve karar vericiler.
> **Soru:** Kurumun zaten bir F5 / NetScaler'ı ve firewall'ı var. OpenIDX araya
> nasıl girer, mevcut trafiği bozmadan nasıl kademeli geçilir, nasıl demo edilir?

**Tek cümlelik cevap:** OpenIDX **ikinci bir yük dengeleyici değildir**. Kurumun
LB'si trafik dağıtmaya devam eder; OpenIDX araya **kimlik ve politika katmanı**
(policy enforcement point) olarak girer. Bu yüzden çoğu senaryoda kurumun VIP'i,
sertifikası ve mevcut trafik yolu **hiç değişmez**.

Tüm örneklerde saha değerleri `<KOSELI>` biçiminde placeholder'dır; kendi
alan adlarınız/IP'lerinizle değiştirin.

---

## 1. Karar tablosu — hangi topoloji size uygun

Önce buraya bakın; detaylar sonraki bölümlerde.

| Durumunuz | Seçin | Trafik yolu değişir mi? | Firewall'da yeni **inbound** kural |
|---|---|---|---|
| LB'ye dokunmak serbest, tam ZTNA isteniyor | **A – LB önde, OpenIDX arkada** | Evet (LB → OpenIDX → uygulama) | Hayır (LB zaten içeride) |
| "Trafiğe dokunmayın" deniyor, sadece yetki denetimi lazım | **B – Sadece yetkilendirme** | **Hayır** | Hayır |
| Pilot kullanıcıyla başlanacak, üretim elleşilmeyecek | **C – Yan yana / DNS** | Hayır (yeni ad üzerinden) | Hayır |
| Uygulama internete hiç açılmasın isteniyor | **D – Clientless overlay** | Evet (tarayıcı → overlay) | **Hayır — sadece outbound** |

**Riski en düşük başlangıç:** C veya B. **En güvenli hedef durum:** D.

---

## 2. Dört entegrasyon topolojisi

### A – LB önde, OpenIDX arkada (klasik, en yaygın)

```
Kullanıcı → [Kurum LB: VIP + sertifika]  →  OpenIDX edge  →  Uygulama
             (değişmez)                     (politika)
```

Kurumun VIP'i ve sertifikası aynı kalır; LB'nin pool'una yeni bir üye
(OpenIDX edge) eklenir. Kimlik doğrulama, cihaz güveni, risk skoru ve kayıt
OpenIDX'te uygulanır.

- **Artı:** tam politika kontrolü, tek noktadan denetim kaydı.
- **Eksi:** trafik yolu değişir → değişiklik penceresi ve testi gerekir.
- **Geri dönüş:** LB pool üyesini eski haline al (tek işlem).

### B – Sadece yetkilendirme (trafiğe hiç dokunmadan)

LB uygulamaya gitmeye devam eder; **her istek için** OpenIDX'e "bu kullanıcı
geçebilir mi?" diye sorar (forward-auth / external auth deseni).

```
Kullanıcı → [Kurum LB] ──sor──► OpenIDX  (izin/ret)
                  └──izinliyse──► Uygulama   (yol değişmedi)
```

Doğrulama uç noktası ve uygulamaya iletilen kimlik başlıkları projede tanımlı:

| Alan | Değer |
|---|---|
| Karar uç noktası | `POST/GET /api/v1/access/auth/decide` |
| OpenIDX'e iletilen | `Authorization`, `Cookie`, `X-Forwarded-For`, `X-Real-IP` |
| Uygulamaya eklenen | `X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Name`, `X-Forwarded-Roles`, `X-Risk-Score` |

> Kaynak: `deployments/docker/apisix/apisix.yaml` (forward-auth örneği) ve
> `internal/access/service.go` (`/auth/decide` rota kaydı).

- **Artı:** trafik yolu **değişmez**, en az müdahale; uygulama kodu değişmez
  (kimlik başlık olarak gelir).
- **Eksi:** LB'de bir kural gerekir; LB ürünü external-auth desteklemeli.
- **Geri dönüş:** kuralı devre dışı bırak (tek işlem).

### C – Yan yana / DNS ile kademeli

Yeni bir ad (`<uygulama>-zt.<kurum>.com`) OpenIDX'e bakar; **eski ad hiç
elleşilmez**. Pilot kullanıcılar yeni adı kullanır.

- **Artı:** üretim trafiği sıfır risk; kullanıcı grubu bazlı genişletme.
- **Eksi:** iki ad bir süre birlikte yaşar.
- **Geri dönüş:** yeni DNS kaydını sil.

### D – Clientless overlay (uygulama internete hiç açılmaz)

Uygulama yayınlanmaz; kullanıcı tarayıcıdan gelir, bağlantı **içeriden dışarı**
kurulmuş bir tünel üzerinden taşınır. Firewall'da uygulama için **inbound kural
yoktur**.

- **Artı:** saldırı yüzeyi en düşük; uygulama "karanlık" kalır.
- **Eksi:** overlay bileşenleri kurulur; bazı uygulamalar (ör. kendi dış IdP'sine
  form_post ile dönenler) ek ayar ister.
- **Geri dönüş:** uygulamanın overlay anahtarını kapat; eski yayın yolu durur.

---

## 3. Firewall: ne açılmalı — ve ne **açılmamalı**

En sık yapılan hata gereğinden fazla port açmaktır. Topolojiye göre gerçekte
gereken minimum:

| Topoloji | Gereken kural | Yön | Gerekmeyen (açmayın) |
|---|---|---|---|
| A – LB önde | LB → OpenIDX edge `:443` | iç ağ | Uygulamaya doğrudan dış erişim |
| B – Yetkilendirme | LB → OpenIDX `:443` (sadece karar çağrısı) | iç ağ | Yeni bir dış inbound yok |
| C – Yan yana | Mevcut LB kuralları yeterli | — | Yeni dış inbound yok |
| D – Clientless | Kurum içi bileşen → denetleyici `1280` + yönlendirici `3022` | **sadece outbound** | **Uygulama portu asla inbound açılmaz** |

**D için kritik nokta:** kurum tarafındaki bileşen **dışarı doğru** bağlanır.
Dolayısıyla kurum firewall'ında uygulama için tek bir gelen kural açılmaz. Bu,
klasik VPN/DMZ yayınına göre belirgin şekilde dar bir yüzeydir.

---

## 4. Kademeli geçiş — 5 aşama, her aşamada tek adımlık geri dönüş

Amaç: üretim trafiğine dokunmadan başlamak, güven arttıkça genişletmek.

### Aşama 0 — Gözlem (trafik yok)
OpenIDX kurulur, hiçbir kullanıcı trafiği almaz. Sağlık uçları ve envanter
doğrulanır.
- **Başarı kriteri:** `/health/ready` **200** dönüyor.
- **Geri dönüş:** servisi durdur; hiçbir şey etkilenmez.

### Aşama 1 — Paralel port (üretim `:443` elleşilmez)
OpenIDX edge, üretimden ayrı bir portta (ör. `<TEST_PORT>`) aynı uygulamayı
sunar. Üretim `:443` çalışmaya devam eder.
- **Başarı kriteri:** test portundan uygulama açılıyor; üretimde 0 değişiklik.
- **Geri dönüş:** test dinleyicisini kapat.

> Bu desen projede zaten mevcuttur: edge yapılandırması hem üretim `443` hem de
> geçiş öncesi test portunu dinleyecek şekilde tanımlıdır
> (`deployments/apisix-edge/config.yaml`).

### Aşama 2 — Tek düşük riskli uygulama
Bir iç uygulama seçilir; C (yeni DNS adı) veya A (LB pool üyesi) ile OpenIDX'e
alınır.
- **Başarı kriteri:** pilot kullanıcılar giriş yapıp çalışıyor; hata oranı ve
  gecikme eşiklerin altında.
- **Geri dönüş:** DNS kaydını sil **veya** LB pool üyesini geri al.

### Aşama 3 — Kademeli genişletme
Kullanıcı grubu bazlı (önerilen) veya yüzde bazlı olarak kapsam büyütülür.
- **Başarı kriteri:** her genişletme adımında destek çağrısında artış yok.
- **Geri dönüş:** kapsamı bir önceki gruba daralt.

### Aşama 4 — Tam geçiş, güvenlik ağıyla
OpenIDX ön tarafa alınır; **taşınmamış her şey için yakalayıcı (catch-all)
kural** eski hedefe gitmeye devam eder.
- **Başarı kriteri:** taşınan uygulamalar OpenIDX'ten, geri kalanı eski yoldan
  sorunsuz çalışıyor.
- **Geri dönüş:** `:443`'ü eski bileşene geri ver.

> Bu "önde yeni edge + yakalayıcı ile eskiye düşme" modeli ve rollback tanımı
> projenin mimari dokümanında da bu şekilde tariflidir
> (`docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md`, §5).

---

## 5. F5 BIG-IP tarafında yapılacaklar

> Aşağıdaki komut/nesne adları **ŞABLON**'dur; sürümünüze göre doğrulayın.
> Kavramlar ürün bağımsızdır: pool + monitor + persistence + SSL profil.

1. **Pool:** OpenIDX edge düğümleri, port `443`.
2. **Monitor (L7 zorunlu):** HTTP(S) monitor, yol `/health/ready`, beklenen `200`.
   L4/ping monitor kullanmayın: süreç ayakta ama bağımlılığı bozuk olabilir.
3. **Persistence:** oturum yapışkanlığı gerekliyse `source_addr` veya cookie.
4. **SSL profil:** istemci tarafında sonlandırın; sunucu tarafına giderken
   **SNI'yi koruyun** (aksi halde çok-alanlı yayınlarda sertifika uyuşmaz).
5. **X-Forwarded-For:** HTTP profilinde XFF ekleme **açık** olmalı
   (aşağıdaki kritik ayar tablosuna bakın).
6. **WebSocket:** WS profili/geçişi açık ve idle timeout uzun olmalı.

**ŞABLON** (doğrulanmadı, sahada teyit edin):
```tmsh
create ltm pool <POOL> members add { <OPENIDX_IP>:443 } monitor <MONITOR>
create ltm monitor https <MONITOR> send "GET /health/ready HTTP/1.1\r\nHost: <FQDN>\r\n\r\n" recv "200"
```

## 6. Citrix NetScaler tarafında yapılacaklar

> Yine **ŞABLON**; NetScaler sürümüne göre doğrulayın.

1. **Service/Service Group:** OpenIDX edge, `SSL` veya `SSL_BRIDGE`, port `443`.
2. **Monitor:** HTTP monitor, `/health/ready`, `200` bekle.
3. **Persistence:** `SOURCEIP` veya `COOKIEINSERT`.
4. **SNI:** sunucu tarafında SNI etkin olmalı.
5. **Client IP:** `-cip ENABLED <HEADER>` ile gerçek istemci IP'si iletilmeli.
6. **WebSocket:** HTTP profilinde WebSocket `ENABLED`.

**ŞABLON** (doğrulanmadı, sahada teyit edin):
```
add lb vserver <VS> SSL <VIP> 443 -persistenceType SOURCEIP
add serviceGroup <SG> SSL
bind serviceGroup <SG> <OPENIDX_IP> 443
```

### Her iki üründe de kritik 5 ayar

| # | Ayar | Neden kritik | Yanlışsa ne olur |
|---|---|---|---|
| 1 | **`OIDX_TRUSTED_PROXIES`** | Gerçek istemci IP'sinin hangi hop'tan okunacağını belirler | **En tehlikelisi.** Yanlışsa istemci `X-Forwarded-For` başlığı uydurabilir; cihaz güveni otomatik onayı, ülke bazlı engelleme, risk skoru, hız sınırı ve **denetim kayıtları** taklit edilebilir hale gelir |
| 2 | **`/health/ready`** (L7 monitor) | Havuz üyeliği gerçekten hazır olana bağlanır | Süreç ayakta ama veritabanı bozukken trafik gönderilir |
| 3 | **Session affinity** | Oturum tutarlılığı | Rastgele oturum düşmeleri |
| 4 | **TLS / SNI** | Çok alan adlı yayında doğru sertifika | Sertifika uyarısı / el sıkışma hatası |
| 5 | **WebSocket + HTTP/1.1** | Canlı akışlar WS kullanır ve **WS yükseltmesi HTTP/1.1 gerektirir** | Bağlantı kurulmuş görünür ama tarayıcı `1006` ile kapatır |

> (1) hakkında: kod bu riski açıkça belgeler — varsayılan olarak yalnızca
> loopback proxy'ye güvenilir; LB loopback değilse bu değişken **mutlaka**
> LB'nin CIDR'ı ile ayarlanmalıdır. Bkz.
> `internal/common/middleware/trustedproxies.go`.
> `*` değeri tüm proxy'lere güvenir ve **önerilmez**.

---

## 7. Bulut ve alternatif yollar

Şirket içi LB tek seçenek değil. Aynı politika katmanı bulutta da aynı yerde
durur: **istemci ile uygulama arasında**.

### 7.1 AWS
- **NLB (L4) + OpenIDX edge:** en yakın "F5 benzeri" model; TLS OpenIDX'te
  sonlanır, SNI sorunu yaşanmaz.
- **ALB (L7) + OpenIDX:** ALB'de sonlandırıp arkaya iletirsiniz; XFF ve
  trusted-proxy ayarı **şart**.
- **EKS üzerinde:** projede AWS için Terraform modülleri mevcuttur
  (VPC, EKS, RDS, ElastiCache ve overlay bileşeni) — `deployments/terraform/`.
- Kubernetes girişi için hazır değerler: `deployments/kubernetes/ingress-nginx-values.yaml`
  (NLB, `externalTrafficPolicy: Local` ile **istemci kaynak IP'si korunur** —
  bu, yukarıdaki 1. kritik ayarla doğrudan ilgilidir).

### 7.2 Azure
- **Application Gateway (L7)** veya **Front Door (global)** öne konur; arkasında
  OpenIDX edge çalışır. Model A ile birebir aynıdır.
- Uygulama Azure'da, kullanıcılar şirket içindeyse: overlay (D) ile uygulamaya
  hiç genel IP vermeden erişim sağlanabilir.

### 7.3 Kubernetes (bulut veya şirket içi)
- Ingress denetleyicisi (`ingress-nginx`) önde, OpenIDX arkada.
- Avantaj: kademeli geçiş **ingress kuralı** seviyesinde yapılır; tek uygulamayı
  taşımak tek bir kural değişikliğidir, geri dönüş de öyle.

### 7.4 Hibrit / SaaS yaklaşımı
- Kontrol düzlemi bulutta, uygulamalar şirket içinde kalır; şirket içinde yalnızca
  **dışarı bağlanan** bir bileşen çalışır (topoloji D). Şubeler ve üçüncü taraflar
  için firewall'da tek bir gelen kural açmadan erişim sağlanır.

### Seçim özeti

| Ortam | Önerilen |
|---|---|
| Klasik veri merkezi, F5/NetScaler var | A (pool üyesi) veya B (yetkilendirme) |
| AWS/Azure, yeni kurulum | Bulut LB önde + OpenIDX arkada |
| Kubernetes | Ingress kuralı ile uygulama bazlı kademeli geçiş |
| Uygulama internete açılmasın | D – clientless overlay |

---

## 8. Sahada gösterilecek 3 demo

### D1 — Sıfır riskli paralel demo (en çok ikna eden)
**Amaç:** üretime dokunmadan aynı uygulamayı yan yana göstermek.
1. OpenIDX edge'i ayrı bir portta (`<TEST_PORT>`) ayağa kaldırın.
2. Aynı uygulamayı iki sekmede açın: biri üretim `:443`, diğeri test portu.
3. **Gösterilecek:** aynı uygulama, ama OpenIDX'li tarafta kimlik doğrulama,
   cihaz kontrolü ve denetim kaydı var.
- **Geri alma:** test dinleyicisini kapat. Üretim hiç etkilenmedi.

### D2 — Yetkilendirme demosu (trafik yolu değişmiyor)
**Amaç:** "LB'mi değiştirmem" diyen müşteriye en az müdahaleyi göstermek.
1. LB'de tek bir external-auth kuralı ekleyin → `/api/v1/access/auth/decide`.
2. Yetkisiz kullanıcıyla deneyin → **reddedilir**.
3. Yetkili kullanıcıyla deneyin → geçer, uygulama `X-Forwarded-User` ile kimliği
   görür.
- **Gösterilecek:** trafik yolu aynı, uygulama değişmedi, yetki artık merkezî.
- **Geri alma:** kuralı devre dışı bırak.

### D3 — Clientless demo (firewall'da inbound kural yok)
**Amaç:** en güçlü güvenlik argümanı.
1. Uygulamanın dışarıya açık bir yayını olmadığını gösterin.
2. Kullanıcı OpenIDX'te oturum açar, listeden uygulamaya tek tıkla girer.
3. **Gösterilecek:** firewall'da bu uygulama için **tek bir gelen kural yok**;
   yalnızca içeriden dışarı bağlantı var.
- **Geri alma:** uygulamanın overlay anahtarını kapat.

**Demo öncesi kontrol listesi**
```bash
# 1) Servis hazır mı (LB monitor'unun bakacağı uç)
curl -s -o /dev/null -w '%{http_code}\n' https://<OPENIDX_FQDN>/health/ready   # 200 bekleniyor

# 2) Uygulama gerçekten cevap veriyor mu (401/302 de "çalışıyor" demektir)
curl -sk -o /dev/null -w '%{http_code}\n' https://<UYGULAMA_FQDN>/

# 3) WebSocket yükseltmesi (HTTP/1.1 ile denenmeli)
curl -sS -i --http1.1 https://<OPENIDX_FQDN>/<WS_YOLU> \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='
# "101 Switching Protocols" bekleniyor
```

---

## 9. Sorun giderme

| Belirti | Olası neden | Kontrol / çözüm |
|---|---|---|
| Denetim kaydında hep LB'nin IP'si görünüyor | `OIDX_TRUSTED_PROXIES` LB'yi kapsamıyor | Değişkeni LB CIDR'ı ile ayarlayın; `*` kullanmayın |
| Cihaz güveni beklenmedik şekilde otomatik onaylanıyor | İstemci `X-Forwarded-For` uyduruyor | Aynı ayar; LB kendi XFF'ini **eklemeli**, istemcininkini güvenmemeli |
| WebSocket kuruluyor gibi ama tarayıcı `1006` ile kapatıyor | WS yükseltmesi HTTP/2 ile denenmiş veya LB WS'i geçirmiyor | HTTP/1.1 ile test edin; LB'de WebSocket'i açın, idle timeout'u artırın |
| Sertifika uyarısı / el sıkışma hatası | Sunucu tarafında SNI iletilmiyor | LB'de SNI'yi koruyun / `upstream host` ayarını doğrulayın |
| Dış IdP ile giriş sonsuz döngüye giriyor | `form_post` geri çağrısı yanlış yoldan dönüyor | Geri çağrının overlay üzerinden gitmesini sağlayın; doğrudan bypass kuralını **kapalı** tutun |
| Listede "hazır" görünen uygulama açılmıyor | Ad DNS'te yok **veya** arkasındaki hedef cevap vermiyor | DNS kaydını ve hedefin gerçekten yanıt verdiğini (401/302 de sayılır) doğrulayın |
| LB havuzdan üye düşürüyor | Monitor L4 veya yanlış yol | `/health/ready` ile L7 monitor kullanın |

---

## Ek: doğrulanmış referanslar

Bu rehberdeki teknik iddiaların dayanağı:

| Konu | Kaynak |
|---|---|
| Edge'in üretim + geçiş öncesi test portunu birlikte dinlemesi | `deployments/apisix-edge/config.yaml` |
| Yeni edge önde + yakalayıcı ile eskiye düşme, rollback modeli | `docs/OPENIDX_CLIENTLESS_EDGE_ARCHITECTURE.md` §5 |
| forward-auth uç noktası ve kimlik başlıkları | `deployments/docker/apisix/apisix.yaml`, `internal/access/service.go` |
| Güvenilir proxy / istemci IP riski | `internal/common/middleware/trustedproxies.go` |
| Sağlık uçları `/health/live`, `/health/ready` | `internal/common/health/health.go` |
| AWS altyapısı (VPC/EKS/RDS/ElastiCache/overlay) | `deployments/terraform/` |
| Kubernetes girişi, NLB ve kaynak IP koruma | `deployments/kubernetes/ingress-nginx-values.yaml` |

> Ürün komutları (**ŞABLON** etiketli olanlar) doğrulanmamıştır; F5/NetScaler
> sürümünüzde teyit ederek uygulayın.
