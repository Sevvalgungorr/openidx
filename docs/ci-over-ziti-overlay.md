# CI runner'ı Ziti overlay üzerinden iç servise bağlamak

> **Kime:** CI/CD ve platform ekipleri.
> **Soru:** Buluttaki bir CI agent'ı (Azure DevOps, GitHub Actions, GitLab), iç
> ağdaki bir servise firewall'da **gelen port açmadan** nasıl erişir?

**Tek cümlelik cevap:** Agent bir Ziti tunneller çalıştırır, kendi kayıtlı
kimliğiyle doğrulanır ve servise overlay üzerinden bağlanır; firewall'da
**hiçbir gelen kural açılmaz**.

Bu belgedeki her davranış çalışan bir kurulumda **ölçülerek** doğrulanmıştır.
Doğrulama komutları bölüm 10'da. Boru hattının arıza davranışını
yerelde sınamak için bölüm 12.

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

## 5. Kimliği Azure DevOps'a koymak

**Kimlik bir pipeline değişkeni OLAMAZ.** Azure değişkenleri **4096 karakterle**
sınırlıdır; kayıtlı kimliğin base64'ü **10.908** karakter. Sıkıştırmak da
kurtarmaz (gzip+base64 hâlâ **5.524**).

| Yol | Boyut | Sonuç |
|---|---|---|
| base64, tek değişken | 10.908 | **Reddedilir** |
| gzip+base64, tek değişken | 5.524 | **Reddedilir** |
| 2 parçaya bölmek | 2.762 ×2 | Çalışır ama kırılgan, birleştirme mantığı gerekir |
| **Secure Files** | sınırsız | **Önerilen** — Microsoft'un bu durum için önerisi |
| Azure Key Vault | sınırsız | En sağlam; ek kurulum ister |

### Secure Files ile

1. Pipelines > Library > **Secure files** > **+ Secure file**
2. Kayıtlı kimlik JSON'unu **`ci-identity.json`** adıyla yükleyin
3. Dosyaya tıklayıp **Pipeline permissions** altında bu pipeline'a yetki verin

Pipeline onu `DownloadSecureFile@1` ile alır; hazır YAML'da tanımlıdır.

> Yetki verilmezse koşum **"Secure file not found"** ile düşer. Hazır YAML bunu
> önden yakalar ve nereye yükleyeceğinizi yazar (test edildi).

### Neden JWT'yi secret yapmıyoruz

JWT kısa (~1.360 karakter, limite sığar) ama **tek kullanımlıktır ve ~3 saat
geçerlidir**. Her koşumda yenisini üretmek gerekirdi — CI için uygun değil.
Uzun ömürlü kimlik bilgisi, kayıttan sonra oluşan JSON'dur.

### Variable group hâlâ gerekli

Kimlik Secure Files'a taşındı, ama diğer değerler grupta kalır:

| Değer | Yer | Neden |
|---|---|---|
| Uygulama API anahtarları | **Grup** (secret) | Kısa sır, pipeline'lar arası paylaşılan |
| Overlay adı/portu, uygulama FQDN'i | **Grup** | Pipeline'lar arası sabit |
| `$(Build.Repository.Name)`, `$(Build.BuildNumber)` | **Pipeline YAML** | Koşuma özel. Gruplar statiktir; içine konan `$(...)` makrosunun genişleyeceği garanti değildir |
| Ziti kimliği | **Secure Files** | 4096 sınırını aşıyor |

> **Sözdizimi tuzağı:** grup referansı **liste** biçimi gerektirir; aynı blokta
> `KEY: value` eşleme biçimiyle karıştırılamaz.

```yaml
variables:
  - group: ZitiCIVars
  - name: ZITI_INTERCEPT_DNS
    value: "<overlay-adi>"
```

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

## 7. Uygulamanın API yüzeyini doğru yoklamak

Bu belgeyi yazarken **yanlış bir sonuca vardım** ve düzeltmek gerekti.

`/api`, `/api/v1`, `/openapi.json` yollarını yokladım, hepsi 404 döndü ve
"uygulamanın API'si yok" sonucuna vardım. **Yanlıştı.** Kök yollar 404
veriyor ama **somut alt yollar yayında**:

| Yol | Sonuç | Anlamı |
|---|---|---|
| `/api` | 404 | Kök yol yayınlanmamış |
| `/api/imports/parsers` | **401** | **Var** — kimlik doğrulama istiyor |
| `/api/imports/upload` | **405** | **Var** — POST bekliyor |
| `/health` | 200 | Frontend'in sağlık ucu |
| `/api/health` | 404 | Backend'de böyle bir yol yok |

**Ders:** bir kök yolun 404 vermesi, altındaki yolların da olmadığı anlamına
gelmez. Çoğu framework yalnızca tanımlı yolları yayınlar. Yokladığınız yolun
gerçekten beklediğiniz yol olduğundan emin olun.

**401 ve 403 başarıdır**, hata değil: yolun var olduğunu ve kimlik
doğrulamanın uygulandığını kanıtlar. Bağlantı testi bu yüzden `200|401|403`
kabul eder.

### Sağlık ucu tek başına yetmez

`/health` frontend tarafından sunulur. Yani host'a erişildiğini kanıtlar, ama
**arkasındaki API'nin yönlendirildiğini kanıtlamaz**. Pipeline bu yüzden iki
şeyi ayrı ayrı kontrol eder:

1. `/health` → gövdede `"status":"ok"` (host erişilebilir)
2. `/api/imports/parsers` → `200|401|403` (API yönlendiriliyor)

İkincisinin gerçekten ayırt ettiği doğrulandı: gerçek uç **401 → geçer**,
uydurma bir yol **404 → düşer**.

---

## 8. Tarama adımı ve sessiz sıfır-bulgu

Upload adımı bir rapor dosyası ister. Pipeline Semgrep ile üretir.

### Format parser ile eşleşmeli

OpenSecOps'ta parser **"Semgrep JSON Report"** adını taşıyor, yani `--json`
çıktısı bekleniyor — **SARIF değil**. İçe aktarıcı parser'ı formata göre
seçtiği için, eşleşmeyen bir dosya **sıfır bulguyla ve "başarılı" diyerek**
içe aktarılır.

### Kural seti seçimi sonucu değiştirir

Gerçek bir `subprocess(..., shell=True)` açığı içeren tek bir dosyada ölçüldü:

| Kural seti | Bulgu |
|---|---|
| `p/ci` | **0** (`errors: []` — temiz tarama gibi görünüyor) |
| `p/default` | 1 |
| `p/python` | 1 |
| `auto` | 1 |

`p/ci` hiçbir hata vermeden sıfır döndü. **Dar bir kural seti, güvenli koddan
ayırt edilemez.** Bu yüzden varsayılan `auto`; `SEMGREP_RULES` ile
değiştirilebilir.

### Tarama bulgu bulunca build düşmemeli

Adım `--error` kullanmaz ve `|| true` ile devam eder. Amaç bulguları
**yayınlamak**; tarama adımı kırmızıya dönerse upload adımına hiç sıra
gelmez ve bulgular OpenSecOps'a **hiç ulaşmaz**.

Doğrulandı: bulgu varken de temiz kodda da `exit=0`.

### "Yeşil" ile "yüklendi" aynı şey değil

Upload adımı üç durumu ayırır:

| Log | Anlamı |
|---|---|
| `NOT UPLOADED: no scan file at ...` | Rapor yok — adım yeşil ama **hiçbir şey yüklenmedi** |
| `UPLOADED` + `findings parsed: N` | Yüklendi ve **ayrıştırıldı** |
| `NOT UPLOADED: rejected (401)` | Reddedildi |

`findings parsed` satırı bilerek eklendi: bir parser hatası yüzünden her
upload `completed` + `findings_count: 0` dönebiliyordu ve HTTP 200 geldiği
için kimse fark etmiyordu. Bulgu beklediğiniz bir boru hattında
`FAIL_ON_ZERO_FINDINGS: "true"` yapın.

---

## 9. Sorun giderme

| Belirti | Sebep | Çözüm |
|---|---|---|
| DNS adı çözülmüyor | `intercept.v1` yok, ya da tunneller root değil | Config'i ekleyin; `sudo` ile çalıştırın |
| `service not found` | service-edge-router policy eksik **veya** kimlikte rol yok | `openidx-serp-<svc>` ve kimliğin rolünü kontrol edin |
| `no terminators` | Bind policy yok, **ya da** router yeni servisi almadı | Bind policy ekleyin; router'ı yeniden başlatın |
| `tls: internal error` | SNI yanlış | `--resolve` kullanın |
| `404 Route Not Found` | Host başlığı yanlış | `--resolve` kullanın |
| İndirme 404 | Tunneller sürümü yok | Yayınlanmış bir sürüm seçin |
| `APPLICATION PROBLEM ... 502` | Overlay **çalışıyor**; origin'in backend havuzu hasta | Bu bizde değil: uygulamanın sahibi ekibe gidin. 2026-08-13'te `/api` 60 denemenin sadece 4'ünde cevap verdi |
| `OVERLAY PROBLEM: no HTTP response` | Hiç HTTP cevabı yok: kimlik, dial policy veya router yolu | Bölüm 9'un ilk satırları + `darkprobe` ile aynı yolu deneyin |
| Import `HTTP 500`, gövde boş | Rapor şekli parser'ı patlatıyor (`extra.metadata` yok, ya da bilinmeyen severity) | Log artık raporun şeklini basıyor; oradan okuyun. Yerel tepki testi: bölüm 12 |

---

## 10. Doğrulama komutları

```bash
# DİKKAT: 'limit' vermezseniz sadece 10 kayıt döner. Bu, var olan nesnelerin
# yok sanılmasına yol açar (bu belgeyi yazarken bizzat yaşandı).
ziti edge list services 'limit 200'
ziti fabric list terminators 'limit 200'      # servis için boş OLMAMALI

# Yetkili erişim (200 + sağlık gövdesi bekleriz)
# DARKPROBE_SNI ŞART: uygulama sertifikayı SNI ile seçer, servis adını SNI
# olarak göndermek el sıkışmayı düşürür ve bu "erişilemiyor" gibi okunur.
DARKPROBE_TLS=1 DARKPROBE_SNI=<app-fqdn> DARKPROBE_HOST=<app-fqdn> \
  go run ./tools/darkprobe <kimlik>.json <servis> /health

# Yetkisiz erişim: servis LİSTEDE BİLE olmamalı.
# Beklenen tek kabul edilebilir çıktı: service '<ad>' not found
# (mesaj STDERR'e gider; `go run` ayrıca "exit status 1" basar, bu normaldir).
# Yalnızca "DENIED" görmek YETMEZ: prob her başarısızlıkta bu öneki basar,
# TLS düştüğünde de. Erişilebilir bir servis bile SNI'sız denenirse "DENIED"
# döner; bu bir sahte yeşildi ve ölçüldü.
DARKPROBE_TLS=1 go run ./tools/darkprobe <kimlik>.json <yetkisiz-servis> /health
```

---

## 11. Geri alma

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

## 12. Boru hattının arıza davranışını yerelde sınamak

Bu bölüm pipeline'ı **değiştirmeden önce** çalıştırılır. Ölçtüğü şey karşı
tarafın sağlığı değil, **bizim tepkimizdir**: origin bozulduğunda boru hattı
doğru katmanı mı suçluyor, yoksa yanlış ekibi mi arattırıyor.

```bash
bash scripts/ci-overlay-score.sh                       # skor  -> SCORE=15/15
bash deployments/ci/faulttest/run-fault-matrix.sh      # kapı  -> FAULT_MATRIX=14/14
bash deployments/ci/faulttest/run-fault-matrix.sh --stat 8   # bilgi -> FLAP_STAT=n/8
```

Skorbord saha değerlerini ortam değişkeninden alır, bu makineye çakılı
değildir:

```bash
APP_HOST=app.example.org ZITI_CONTAINER=my-controller SERVICE=myapp \
  bash scripts/ci-overlay-score.sh
```

Matris sonucu ayrıca `/tmp/cifault/last-result` dosyasına **zaman ve commit
damgasıyla** yazılır (`FAULT_MATRIX_RESULT` ile değiştirilebilir). Böylece bir
skorbord 3 dakikalık matrisi her seferinde yeniden koşmadan sonucu okuyabilir.
Önbelleklenmiş kanıt tehlikelidir, o yüzden okuyan taraf **eskitmelidir**:
6 saatten eski ya da başka bir commit'e ait sonuç `STALE` / `OTHER_SHA` sayılır
ve **geçer not değildir**. Kanıt yoksa sonuç *bilinmiyor*, "başarılı" değil.

**Ama önbellek, ancak ölçüm gerçekten pahalıysa savunulabilir.** Overlay
erişimi (`OVERLAY_REACH_200`) ve yetkisiz reddi (`UNAUTH_DENIED`) uzun süre
elle tazelenen dosyalardan okundu; gerekçe "gerçek bir tüneller koşusu her
puanlamada tekrarlanamaz" idi. Bu **ölçümle çürüdü**: `tools/darkprobe` aynı
dial'i **0,14 saniyede** yapıyor. Artık skorbord bu ikisini **canlı ölçer**;
kimlik dosyası ya da `go` yoksa eskitilen dosyaya düşer, o da yoksa
`0 = bilinmiyor`. Ucuza üretilebilen kanıt asla önbelleğe alınmamalıdır.

Bu geçiş, önbelleğin gizlediği **iki ölçüm kusurunu** ortaya çıkardı:

1. **Yanlış kırmızı.** Reddedilme mesajı stdout'a değil **stderr**'e gidiyor;
   `2>/dev/null` yüzünden metrik **çalışan** sistemde 0 okudu.
2. **Sahte yeşil.** Kalıp `DENIED` kelimesini de kabul ediyordu, ama prob *her*
   başarısızlıkta aynı öneki basar — TLS el sıkışması düştüğünde de. Kimliğin
   **gerçekten gördüğü** bir servis, SNI verilmediğinde `DENIED ... tls:
   internal error` döndü ve metrik **yine 1** okudu. Yani metrik "servisi
   göremiyor"u değil "istek başarısız oldu"yu ölçüyordu. Artık yalnızca
   Ziti'nin `service '<ad>' not found` cevabı sayılır.

Parametrelerin dekoratif olmadığı mutasyonla kanıtlı (sahte değer skoru
**düşürür**): `SERVICE=yoksun` → 9/15, `DENY_SERVICE=<görülen servis>` → 14/15,
`CI_IDENTITY` yok → 13/15, `APP_HOST=yok.invalid` → 13/15,
`ZITI_CONTAINER=yoksun` → 7/15.

Matris, adımı **ayrıştırılmış YAML'den çıkarıp gerçekten çalıştırır**; kaynak
dosyada metin araması yapmaz. Böylece YAML'e gömülü kabuk kodunun kendisi
sınanır.

| Senaryo | Origin ne yapıyor | Boru hattı ne demeli |
|---|---|---|
| `healthy` | her şey 200/401 | `reachable over the overlay`, rc=0 |
| `dead_api` | `/` 200, `/api` 502 | `APPLICATION PROBLEM` — **overlay değil**, rc=1 |
| `flapping` | `/api` ancak N denemede bir cevaplıyor | `API routed`, rc=0 (yeniden deneme işini yapmalı) |
| `no_route` | hiç dinleyen yok | `OVERLAY PROBLEM`, rc=1 |
| `api_500` (upload) | import 500 dönüyor | `SERVER-side exception`, rc=1 |
| `healthy` (upload) | import 201 | `findings parsed`, rc=0 |

### Bu döngünün bulduğu gerçek kusurlar

Bunlar tahmin değil, testin ürettiği ölçümlerdir:

1. **Ölü kod.** Bağlantı reddedildiğinde `curl` 7 ile çıkıyor ve `set -e`
   yüzünden adım, `OVERLAY PROBLEM` dalına **hiç ulaşamadan** ölüyordu. En çok
   ihtiyaç duyulan mesaj asla basılmıyordu.
2. **Şansla geçen yeniden deneme.** 12 deneme, ölçülen %7 başarı oranında
   `0.93^12` = **%42 kaçırır**. Canlıda 5/5 geçmişti; bu şanstı. 40'a çıkarıldı
   (~%5). Sağlıklı durumda ilk denemede çıkılır, maliyeti yoktur.
3. **Kaymış mesaj.** Döngü 40 denerken metin hâlâ `after 12 tries` diyordu;
   sayı üç yere kopyalanmıştı. Tek `tries` değişkenine bağlandı.

### Kapı neden deterministik, "gerçekçi" değil

İlk sürüm gerçek %7 oranını doğrudan kullanıyordu, bu yüzden **matrisin kendisi**
20 koşudan birinde ortada bir sorun yokken 5/6 veriyordu. Yirmi koşuda bir yanlış
alarm veren kapı, insanlara kapıyı yok saymayı öğretir; bu, kapı olmamasından
kötüdür ve "tekrar çalıştır geçer" gerçek regresyonların elden kaçtığı yerdir.

Bu yüzden iki soru ayrıldı:

- **Kapı** evet/hayır sorar (döngü, çok sayıda hatadan sonra cevap veren bir
  backend'i atlatabiliyor mu) ve deterministik bir taklit kullanır: her 20.
  istekte başarı. 20 sayısı keyfi değil — eski 12'den büyük olduğu için o
  kusuru hâlâ yakalar, 40'tan küçük olduğu için doğru döngü **her zaman** geçer.
- **İstatistik** ayrı koşar (`--stat`) ve pass/fail değildir.

Boru hattında bunun için hiçbir şey değişmedi; yeniden deneme sayısı 40 kaldı.
Sadece test yazı-tura olmaktan çıktı.

### Yeşil bir kapı, ölçtüğü **dallar** kadar değerlidir

Matris uzun süre `6/6` bastı. Doğruydu, ama yükleme adımının yalnızca **iki**
dalını ölçüyordu: 500 ve mutlu yol. Diğer dallar (**401/403**, **422**,
`findings_count=0`, **rapor yok**) repoda yazılıydı ve **hiçbir koşumda
çalışmıyordu**. Ölçülmeyen bir dal bozulduğunda hiçbir şey kırmızı olmaz.

En sinsisi `findings_count=0`: API **201** döner, adım **yeşil** kalır, hiçbir
bulgu yayımlanmaz. Bu kusur bu projede bir kez yaşandı; testi ancak şimdi var.

İki vaka origin davranışı değil **çağıran taraf koşuludur** (`zero_find_strict`
opt-in kapı, `no_report` eksik dosya); sağlıklı origin + tek ortam değişkeniyle
aynı tabloda ölçülür, yorum satırında kalmaz.

Skorbord hedefi bu yüzden sabit sayı değil **orandır**. `6/6` beklemek, matrise
yeni arıza vakası ekleyen kişiyi skor kaybıyla cezalandırıp **kapsamı
dondururdu**. `0/0` (boş matris) geçerli sayılmaz.

### Testlerin kendisi sınandı (mutasyon)

Bir test, kırılmış kodu **kırmızıya çevirebildiği** ölçüde testtir:

| Mutasyon | Sonuç |
|---|---|
| katman mesajını sil | 4/4 → 3/4 |
| yeniden denemeyi kaldır | `flapping` kırmızı |
| 500 mesajını genelleştir | tam → bir eksik |
| `tries` 40 → 12 | tam → **bir eksik** (ölçüldü) |
| 401 dalı `exit 1` → `exit 0` | `bad_key` **HATA** (ölçüldü) |
| sıfır-bulgu kapısı `if false` | `zero_find_strict` **HATA** (ölçüldü) |
| 'rapor yok' `exit 0` → `exit 1` | `no_report` **HATA** (ölçüldü) |
| 422 dalını sil | `bad_type` mesajı **HATA** (ölçüldü) |
| kayıp `#`'i geri koy | `bash -n` **geçiyor**, prose kontrolü **yakalıyor** |
| bulgu karşılaştırmasını sil | `mismatch` + `mismatch_strict` **HATA**, `healthy` temiz (ölçüldü) |
| isim-çözümleme korumasını kaldır | 14/14 → **13/14**, yalnızca `no_resolve` düşüyor (ölçüldü) |

### 12.0 SBOM: kodumuz değil, taşıdığımız bağımlılıklar

Semgrep **bizim kodumuzu** okur; sevk ettiğimiz bağımlılıklar hakkında hiçbir
şey söylemez — CVE'lerin çoğu ise orada yaşar. OpenSecOps `/api/imports/sbom`
kazandığı için pipeline artık bulguların yanında bir **bileşen envanteri** de
gönderebiliyor (`UPLOAD_SBOM=true` ile açılır, varsayılan kapalı).

Yazmadan **önce** canlı API'ye overlay üzerinden ölçüm yapıldı:

| endpoint | yanıt | sonuç |
|---|---|---|
| `/api/imports/sbom` | GET'e **405** | var, POST bekliyor → adım yazıldı |
| `/api/imports/archive` | **404** | **yok** → bağlanmadı |

İkincisini tahminle eklemek, her koşuda 404 alan ve `|| true` yüzünden hep
sağlıklı görünen bir adım üretirdi.

Ölçülen davranış (bu makineden, gerçek overlay üzerinden):

| durum | sonuç |
|---|---|
| syft ile envanter (openidx deposu) | **2303 bileşen** |
| bağımlılığı olmayan depo | `components inventoried: 0` + gürültülü uyarı |
| geçersiz anahtar | HTTP **401**, sebebi yazılı, `rc=1` |
| endpoint kaybolursa | HTTP **404**, "API değişti", `rc=1` |

Sıfır bileşenli SBOM, sıfır dosyalık taramanın aynı tuzağı: temiz yüklenir ve
hiçbir şey bildirmez. Bu yüzden varsayılan olarak **gürültülü**, yalnızca
`FAIL_ON_EMPTY_SBOM=true` ile ölümcül.

### 12.0.1 Sessizce ölen adım: isim çözülmezse

Dört adım da `ip="$(getent hosts ...)"` ile başlıyordu. `set -euo pipefail`
altında getent başarısız olduğunda adım **tek kelime etmeden** ölüyordu — ve
bu, çalışma zamanının **en olası** arızası. Bu makinede birebir gözlendi:
tünel ayakta, `/health` 200, ama `secops.ziti` çözülmüyor ve SBOM adımı
`RC=0` ile sessizce bitiyordu.

Artık dördü de sebebi söyleyip `rc=1` veriyor, ve bu matriste `no_resolve`
vakası olarak kalıcı: korumayı kaldırınca **14/14 → 13/14**, yalnızca kendi
vakası düşüyor.

### 12.1 `bash -n`'in yakalayamadığı sınıf

Bir yorum satırının başındaki `#` düzenleme sırasında düştü. Sonuç
**sözdizimsel olarak geçerliydi**: `bash -n` geçti, matris tam puan bastı, tek iz
stderr'deki `THIS: command not found` satırıydı. **İki merge edilmiş PR boyunca
fark edilmedi**; temiz bir klonda çalıştırırken tesadüfen görüldü. Tehlikeli
şekil budur: başarı raporlarken sessizce çöp çalıştıran bir betik. Aynı kayma
bir satır aşağıda, `set -e` altında, koşumu öldürürdü.

```bash
bash scripts/check-shell-prose.sh        # tarama    -> PROSE_IN_SHELL=0
bash scripts/check-shell-prose.test.sh   # kapının kendi testi -> OK
```

Her ikisi de CI'da `No prose running as shell` işinde koşar (`.github/workflows/ci.yml`),
docs-only atlamasının dışındadır. Kural **kasten dardır**: satır yorum
değilse, iki yorum satırı arasındaysa, 4+ kelimeyse, kabuk metakarakteri
içermiyorsa, bilinen bir komutla başlamıyorsa ve düzyazı noktalaması
taşıyorsa uyarır. Son iki kural, ilk sürümün gerçek kod üzerinde ürettiği bir
yanlış pozitiften doğdu (`rm -rf build dist node_modules`): **çalışan bir satırı
işaretleyen kontrol, insanlara `--no-verify` öğretir.**

Kapının kendisi de test edilir, çünkü **kırmızıya dönemeyen bir kapı, hiçbir
şey ifade etmeyen yeşil bir tiktir** — bu repo bunu bir kez öğrendi:
`check-no-internal-topology.sh`'in ilk sürümü geçersiz bir grep bayrağıyla, iç
adres **içeren** bir ağaçta geçiyordu. Kapının koruma sağladığı, kasıtlı kusurlu
bir dalla canlı doğrulandı: o dalda iş **kırmızı**, temiz dalda **yeşil**.

### Kanıtlanmayan tek şey

Gerçek import 500'ü **bu makineden doğrulanamaz**: API anahtarı Azure tarafında
bir secret'tır ve burada yoktur. Sahte origin tam da bu yüzden bir anahtar
üretir. Yani kanıtlanan şey **500'e verilen tepkidir**, 500'ün ortadan kalktığı
değil. Gerçek doğrulama pipeline yeniden koştuğunda olur; log artık raporun
şeklini kendisi yazdırdığı için sebep tahmin edilmez, okunur.

---

## Ek: firewall açısından özet

| Yön | Kural |
|---|---|
| CI agent → dışarı | Controller (1280/TCP) ve router (3022/TCP) |
| CI agent → içeri | **Hiçbiri** |
| İç uygulama → içeri | **Hiçbiri** — router zaten iç ağdadır |

Uygulamanın portu internete **hiç açılmaz**.
