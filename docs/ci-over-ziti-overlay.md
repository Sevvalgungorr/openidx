# CI runner'ı Ziti overlay üzerinden iç servise bağlamak

> **Kime:** CI/CD ve platform ekipleri.
> **Soru:** Buluttaki bir CI agent'ı (Azure DevOps, GitHub Actions, GitLab), iç
> ağdaki bir servise firewall'da **gelen port açmadan** nasıl erişir?

**Tek cümlelik cevap:** Agent bir Ziti tunneller çalıştırır, kendi kayıtlı
kimliğiyle doğrulanır ve servise overlay üzerinden bağlanır; firewall'da
**hiçbir gelen kural açılmaz**.

Bu belgedeki her davranış çalışan bir kurulumda **ölçülerek** doğrulanmıştır.
Doğrulama komutları bölüm 8'de.

---

## 1. Neden bu yol

Klasik seçenekler ve sorunları:

| Yaklaşım | Sorun |
|---|---|
| Servisi internete aç | Saldırı yüzeyi; CI için açılan port herkese açıktır |
| CI agent IP'lerini beyaz listeye al | Bulut agent IP'leri paylaşımlı ve değişken; liste hem çok geniş hem sürekli bozulur |
| Self-hosted agent + VPN | VPN tüm ağa erişim verir; CI'ın tek bir servise ihtiyacı vardır |
| **Ziti overlay** | Kimlik başına **tek servise** erişim, gelen port yok, erişim tek politikayla geri alınır |

Overlay'de yetkisiz bir kimlik servisi **göremez bile** — bağlanamamakla kalmaz,
varlığını öğrenemez. Ölçüldü: yetkisiz kimlik `service 'secops' not found` alır.

---

## 2. Kurulması gereken zincir

Bu altı nesnenin **her biri** gereklidir ve eksik olan her biri **sessiz bir
çıkmaz** üretir:

| Nesne | Yoksa ne olur |
|---|---|
| `intercept.v1` config | Tunneller'a yakalayacak adres vermez → CI'da DNS **timeout** |
| `host.v1` config | Router'ın nereye ileteceği belirsiz |
| Servis | — |
| **Bind** policy | Terminator oluşmaz → `no terminators` |
| **Dial** policy | Kimlik servisi göremez |
| **edge-router** policy | Kimlik hiçbir router'ı kullanamaz |
| **service-edge-router** policy | Kimlik doğrulanır ama `service not found` alır — yetki hatası gibi görünür, aslında **yönlendirme** hatasıdır |

> **Sık yapılan hata:** Yalnızca `host.v1` taşıyan bir servis BrowZer ile
> (tarayıcıdan) erişilebilir, ama bir tunneller ona **bağlanamaz** — çünkü
> yakalayacağı bir adres yoktur. CI için `intercept.v1` şarttır.

Kurulum tek komutla:

```bash
TARGET_HOST=<ic-uygulama-adresi> \
  deployments/ci/setup-ci-overlay-access.sh --identity ci-<takim>
```

Script **idempotent**: ikinci koşuda hiçbir şey yeniden oluşturulmaz
(ölçüldü: ilk koşu 6 nesne, ikinci koşu 0). `DRY_RUN=1` ile önce ne
yapacağını gösterir.

---

## 3. Router adresi koda hiç yazılmaz

En sık sorulan soru: *pipeline'da public router adresi nerede?* **Hiçbir
yerde.** Ne YAML'da, ne kimlik dosyasında. Bu kasıtlı bir tasarım.

Zincir ölçülerek doğrulandı:

**a) Kayıt JWT'sinde yalnızca controller vardır.** Router yok:

```
iss   = https://<controller>:1280
ctrls = ['tls:<controller>:1280']
em    = ott          # one-time token
```

**b) Kayıttan sonra oluşan kimlik dosyasında da router yoktur.** Yalnızca
`ztAPI` (controller adresi) ve istemcinin sertifikası/anahtarı bulunur.
Dosyada router adresi araması **boş döner**.

**c) Router kendi adresini kendisi ilan eder.** Router'ın yapılandırmasındaki
`advertise` alanı, controller'a kaydolurken controller'a bildirilir:

```
advertise: <router-fqdn>:3022     # router config
```

**d) Controller bunu saklar ve çalışma anında istemciye verir:**

```json
{"tls": "tls://<router-fqdn>:3022", "wss": "wss://<router-fqdn>:3023"}
```

**e) Hangi router'ı göreceğini `edge-router-policy` belirler:**

```
ci-clients-erp: kimlik=['#ci-clients'] router=['#all']
```

Yani CI agent'ı yalnızca controller'a bağlanır, kimliğini doğrular, ve
controller ona **o kimliğin yetkili olduğu** router'ların adresini döner. Canlı
kanıt (bağlantı günlüğünden):

```
router=tls:<router-fqdn>:3022   status=200
```

### Bunun pratik sonuçları

| Durum | Ne yapmanız gerekir |
|---|---|
| Router'ın adresi/IP'si değişti | **Hiçbir şey.** Router'ın `advertise` değeri güncellenir, istemciler yeni adresi otomatik alır |
| İkinci bir router eklendi | **Hiçbir şey.** Politika izin veriyorsa istemci onu da görür; yük ve yedeklilik kendiliğinden gelir |
| CI'ın erişimini kesmek | Kimliği silin veya rolünü kaldırın. Pipeline'a **dokunulmaz** |
| Bir CI'ı başka bir sahaya taşımak | Aynı YAML; yalnızca secret değişir |

Bu yüzden pipeline'da IP, port yönlendirmesi veya router adresi **yoktur** —
tek yapılandırma controller adresidir ve o da kimlik dosyasının içindedir.

---

## 4. Kimlik ve secret yönetimi

```bash
# 1) kimlik + tek kullanımlık JWT üret
TARGET_HOST=<adres> ./setup-ci-overlay-access.sh --identity ci-takim

# 2) BİR KEZ kaydol -> uzun ömürlü kimlik dosyası
ziti-edge-tunnel enroll --jwt ./ci-takim.jwt --identity ./ci-takim.json

# 3) secret olarak sakla, yerelden sil
base64 -w0 ./ci-takim.json     # -> ZITI_CI_IDENTITY_B64 (SECRET)
shred -u ./ci-takim.json ./ci-takim.jwt
```

- **JWT tek kullanımlıktır ve kısa ömürlüdür** (varsayılan ~3 saat). Uzun
  ömürlü kimlik bilgisi, kayıttan sonra oluşan **JSON**'dur.
- İkisi de **asla** repoya girmez.
- Erişimi iptal etmek: kimliği silmek ya da `ci-clients` rolünü kaldırmak
  yeterlidir. Servis tarafında hiçbir değişiklik gerekmez.

---

## 5. Secret'ı Azure DevOps'a eklemek (otomatik değildir)

**Secret kendiliğinden oluşmaz.** YAML dosyasını repoya koymak yetmez; değişkeni
Azure tarafında elle tanımlamanız gerekir. İki yol var:

**Tek pipeline için:** Pipeline > Edit > Variables > New variable
- Name: `ZITI_CI_IDENTITY_B64`
- Value: `base64 -w0 <kimlik>.json` çıktısı
- **Keep this value secret** kutusunu işaretleyin

**Birden çok pipeline için (önerilen):** Pipelines > Library > Variable group
oluşturun, değişkeni oraya koyup kilit simgesiyle secret yapın, sonra YAML'a
ekleyin:

```yaml
variables:
  - group: ziti-ci
  - name: ZITI_INTERCEPT_DNS
    value: "<overlay-adi>"
```

> **Not:** Secret değişkenler script adımlarına **otomatik geçmez**. Adımın
> `env:` bloğunda açıkça eşlenmeleri gerekir — hazır YAML'da bu yapılmıştır.
> Bu, secret'ların yanlışlıkla alt süreçlere sızmasını önleyen bilinçli bir
> Azure davranışıdır.

### Yanlış kurulum sessizce başarısız olmaz

Değişken tanımlı değilse Azure `$(ZITI_CI_IDENTITY_B64)` metnini **olduğu gibi**
geçirir. Kontrol edilmezse `base64` kısa bir bozuk dosya yazar ve koşum çok
sonra anlaşılmaz bir kayıt hatasıyla ölür. Pipeline bu yüzden dört durumu
önden ayırt eder (hepsi test edildi):

| Durum | Mesaj |
|---|---|
| Değişken yok | `ZITI_CI_IDENTITY_B64 is not set.` |
| Makro çözülmemiş | `ZITI_CI_IDENTITY_B64 is not set.` |
| Bozuk base64 | `ZITI_CI_IDENTITY_B64 is not valid base64.` |
| JWT konmuş (kayıtlı JSON yerine) | `no ztAPI field` + kayıt komutu |

Son satır en sık yapılan hatadır: **JWT tek kullanımlıktır**, uzun ömürlü
kimlik bilgisi kayıttan sonra oluşan **JSON**'dur.

---

## 6. Pipeline

Hazır dosya: `deployments/ci/azure-pipelines-ziti.yml`

Üç kritik nokta:

**1. Tunneller sürümü controller sürümü DEĞİLDİR.**
`ziti-tunnel-sdk-c` ve `openziti/ziti` ayrı projelerdir, ayrı sürüm hatları
vardır. İkisini eşitlemeye çalışmak kalıcı bir kırılma kaynağıdır — var olmayan
bir etikete işaret eden indirme **404** verir ve pipeline ilk adımda çöker.

**2. `ziti-edge-tunnel run` root ister.** TUN cihazı oluşturur ve overlay DNS
adının `curl` gibi sıradan araçlarca çözülebilmesi için resolver kurar.

**3. TLS/Host uygulamanın gerçek adını taşımalıdır.** Bağlantı overlay adı
üzerinden kurulur, ama uygulama sertifikasını **SNI'ya** göre seçer ve isteği
**Host** başlığına göre yönlendirir. Yanlışsa:

| Belirti | Sebep |
|---|---|
| `tls: internal error` | SNI overlay adını taşıyor |
| `404 Route Not Found` | Host başlığı overlay adını taşıyor |

Doğru kalıp — `--resolve` ile ad gerçek, bağlantı overlay üzerinden:

```bash
ip="$(getent hosts "$ZITI_INTERCEPT_DNS" | awk '{print $1}' | head -1)"
curl -sSf --resolve "${APP_HOST}:443:${ip}" "https://${APP_HOST}/health"
```

**Sağlık kontrolünde 200 tek başına kanıt değildir.** Araya giren bir proxy de
200 döndürebilir. Gövdeyi de doğrulayın:

```bash
echo "$body" | grep -q '"status":"ok"' || exit 1
```

---

## 7. Sorun giderme

| Belirti | Sebep | Çözüm |
|---|---|---|
| DNS adı çözülmüyor | `intercept.v1` yok, ya da tunneller root değil | Config'i ekleyin; `sudo` ile çalıştırın |
| `service not found` | service-edge-router policy eksik **veya** kimlikte rol yok | `openidx-serp-<svc>` ve kimliğin rolünü kontrol edin |
| `no terminators` | Bind policy yok, **ya da** router yeni servisi almadı | Bind policy ekleyin; router'ı yeniden başlatın |
| `tls: internal error` | SNI yanlış | `--resolve` kullanın |
| `404 Route Not Found` | Host başlığı yanlış | `--resolve` kullanın |
| İndirme 404 | Tunneller sürümü yok | Yayınlanmış bir sürüm seçin |

---

## 8. Doğrulama komutları

```bash
# DİKKAT: 'limit' vermezseniz sadece 10 kayıt döner. Bu, var olan nesnelerin
# yok sanılmasına yol açar (bu belgeyi yazarken bizzat yaşandı).
ziti edge list services 'limit 200'
ziti fabric list terminators 'limit 200'      # servis için boş OLMAMALI

# Yetkili erişim (200 + sağlık gövdesi bekleriz)
DARKPROBE_TLS=1 DARKPROBE_SNI=<app-fqdn> DARKPROBE_HOST=<app-fqdn> \
  go run ./tools/darkprobe <kimlik>.json <servis> /health

# Yetkisiz erişim ("service not found" bekleriz)
DARKPROBE_TLS=1 go run ./tools/darkprobe <rolsuz-kimlik>.json <servis> /health
```

---

## 9. Geri alma

```bash
SERVICE=<svc> TARGET_HOST=<adres> ./setup-ci-overlay-access.sh --rollback
```

Yalnızca **o servise ait** nesneleri siler. Paylaşılan edge-router politikası ve
kimlikler **korunur**.

> Bu ayrım deneyerek öğrenildi: script'in ilk sürümü rol bazlı edge-router
> politikasını da siliyordu; tek bir servisin geri alınması, **aynı rolü
> paylaşan başka bir CI kimliğinin tüm router erişimini** anında kesiyordu.
> Paylaşılan nesneler artık yalnızca oluşturulur, asla silinmez.

---

## Ek: firewall açısından özet

| Yön | Kural |
|---|---|
| CI agent → dışarı | Controller (1280/TCP) ve router (3022/TCP) |
| CI agent → içeri | **Hiçbiri** |
| İç uygulama → içeri | **Hiçbiri** — router zaten iç ağdadır |

Uygulamanın portu internete **hiç açılmaz**.
