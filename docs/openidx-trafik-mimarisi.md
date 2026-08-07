# OpenIDX Trafik Yönetimi Mimarisi: Yük Dengeleme, Bulut ve Karanlık Uygulamalar

Bu belge dört soruyu yanıtlar:

1. OpenIDX yük dengeleyici olarak çalışabilir mi?
2. Cloudflare gibi bir kenar (edge) katmanı olabilir mi?
3. Azure gibi bulutta koşabilir mi?
4. İç sistemleri Ziti ile kapatmak mümkün mü, arkadaki uygulamalar nasıl entegre olur?

Her iddia bu ortamda **ölçülerek** doğrulanmıştır; ölçülemeyen hiçbir şey "çalışıyor" diye yazılmamıştır.

---

## 1. Mimari kararlar ve gerekçeleri

Kararlar dört eksende değerlendirildi: **stabilite**, **maliyet**, **ölçek**, **uygulanabilirlik**.

### K1 — Veri düzlemi APISIX kalır; Go içinde yük dengeleyici yazılmaz

| Eksen | Değerlendirme |
|---|---|
| Stabilite | APISIX/OpenResty yıllardır sahada; dengeleme, sağlık kontrolü, hız sınırı savaş görmüş kod |
| Maliyet | Sıfırdan yazmak yıllar alır; mevcut motor ücretsiz ve zaten kurulu |
| Ölçek | Nginx olay döngüsü ile bağlantı başına maliyet düşük |
| Uygulanabilirlik | **Ölçüm:** üretimde `server: APISIX/3.15.0` başlığı 443'ü servis ediyor; programatik yönetim (`apisix_client.go` + `apisix_reconciler.go`) zaten mevcut |

**Karar gerekçesi:** Go'da yük dengeleyici yazmak, üç yıllık olgunluğu sıfırdan üretmek demektir. Üretilen rota gövdesi zaten `upstream.type=roundrobin` ve `nodes` haritası içeriyordu; eksik olan motor değil, **niyeti ifade edecek yerdi**.

### K2 — Go kontrol düzlemidir, istek yolunda durmaz

İstek başına Go'dan geçmek gecikme ve arıza yüzeyi ekler. OpenIDX **niyet** üretir (kim, hangi cihaz, hangi risk), APISIX **uygular**.

**En değerli sonucu:** kontrol düzlemi tamamen dursa bile trafik akmaya devam eder. Kimlik kararları önceden hesaplanmış politika olarak kenarda durur.

### K3 — CDN / anycast / DDoS **hedef değildir** (açık kapsam beyanı)

Bu, sessizce düşürülen bir özellik değil, bilinçli bir kapsam kararıdır.

Cloudflare'ın asıl değeri küresel **anycast PoP ağıdır**: dünyanın her yerinde sunucu, BGP anycast, terabit ölçekli emme kapasitesi. Bu bir **altyapı yatırımıdır**, yazılım özelliği değil. Yazılımla taklit edilemez.

**OpenIDX'in hedefi farklı bir katman:** *kimlik-farkında uygulama kenarı*. Cloudflare'ın bilemediğini biz biliriz — kullanıcı kim, cihazı güvenli mi, risk skoru kaç, hangi gruba üye. Konumlandırma: **Cloudflare'ın yerine değil, arkasında.** İkisi birlikte kullanılabilir.

### K4 — Önce stabilite, sonra özellik

Ölçüm sırasında üretimde **çalışmayan hostlar** bulundu. Yeni özellik eklemeden önce onlar onarıldı (bkz. §2).

### K5 — Çoklu upstream ayrı tabloda, `to_url` bozulmadan

`proxy_routes.upstream_pool_id` **NULLABLE** ve varsayılan NULL. NULL = "`to_url`'i aynen kullan". Mevcut her satır NULL olduğu için **bugün çalışan hiçbir rotanın davranışı değişmez**. Ölçüldü: 8 rotanın 8'i de NULL kaldı, davranış farkı **0**.

---

## 2. Bulunan ve onarılan üretim sorunu

Ölçüm iki başlangıç teşhisimi çürüttü. İkisi de düzeltildi:

| İlk teşhis | Ölçüm sonucu |
|---|---|
| "İki APISIX de 443'e bind, çakışıyor" | **Yanlış.** 443'ü tek örnek tutuyor |
| "Güvenilen proxy ayarı yok = açık" | **Yanlış.** Kod güvenli varsayılan kullanıyor (yalnız loopback) |

**Asıl sorun daha ciddiydi:** OpenIDX'in kenarı 443'ü devralmış ama üçüncü taraf rotaları taşınmamıştı. `*.tdv.org` joker rotası onları yutup kimlik proxy'sine gönderiyordu.

| Host | Önce | Sonra |
|---|---|---|
| Otomasyon aracı | 404 | **200** |
| Sertifika yöneticisi | 404 | **302** |
| Cihaz yönetimi | 404 → döngü 502 | **503 + anlaşılır mesaj** |
| OpenIDX hostları | 200 | 200 (**değişmedi**) |

Cihaz yönetiminde ayrı bir bulgu: upstream `127.0.0.1:443` **kenarın kendisiydi** (kendine proxy döngüsü). Gerçek arka uç 6 haftadır kapalı. Başka ekibin servisi olabileceği için başlatılmadı; döngü kırılıp açık bir "servis kapalı" yanıtı kondu.

**Geri dönüş provası yapıldı:** tek komutla eski duruma dönüldü, sonra yeniden uygulandı.

---

## 3. Yük dengeleme

### Ne eklendi

`upstream_pools` + `upstream_pool_members` tabloları ve rotadan havuza **opsiyonel** bağlantı.

| Kavram | Anlamı |
|---|---|
| Ağırlık | Trafiğin göreli payı |
| **Ağırlık 0** | **Boşaltma**: üye kayıtlı kalır, sağlık durumu korunur, yeni trafik almaz |
| **Devre dışı** | Üye upstream'den tamamen çıkar, yoklanmaz bile |
| Algoritma | `roundrobin` (yay) veya `chash` (yapışkanlık) |
| Sağlık kontrolü | Aktif yoklama; ölü arka uç otomatik çıkar, düzelince döner |

### Tasarımdaki incelikler

- **Kullanılamaz havuz render edilmez.** Boş upstream üretmek rotayı kara deliğe çevirirdi. Tamamen boşaltılmış havuz "yapılandırılmamış" sayılır, "trafiği düşürecek şekilde yapılandırılmış" değil.
- **Çıktı deterministik.** Uzlaştırıcı her turda yazıyor; sıralama çıktıya sızsaydı her tur "değişiklik" görünür ve veri düzlemini gereksiz çalkalardı.
- **Bilinmeyen algoritma → roundrobin.** `chash`'e düşseydi yanlış yazılmış bir ad bütün trafiği tek arka uca sabitlerdi.
- **İki ayrı eşik.** Tek anlık hata sağlıklı arka ucu atmamalı; tek başarı da hâlâ toparlananı hemen geri almamalı.

### Canlı kanıt

| Senaryo | Sonuç |
|---|---|
| Yük dağılımı | 10 istek → **5/5** |
| **Arka uç öldürüldü** | 60 istek, **kayıp = 0** (sürekli yoklama ile ölçüldü) |
| Arka uç geri geldi | Havuza otomatik döndü, 12 istek → 6/6 |

---

## 4. Karanlık uygulamalar: arkadaki uygulama nasıl entegre olur

**Bu, en önemli bölüm.** Sorunun özü: uygulama internete kapalıyken nasıl erişilir?

### Üç mod, tek soru

Yöneticiye sorulan tek şey: **"Uygulama nerede çalışıyor ve kime açık olmalı?"**

| Mod | Ne zaman | Trafik yolu | Güvenlik duvarı |
|---|---|---|---|
| **direct** | Uygulama zaten kenarın erişebildiği bir ağda | Kenar → uygulama | Değişiklik yok |
| **identity** | Uygulama kimlik bilgisi bekliyor | Kenar → kimlik proxy'si → uygulama | Değişiklik yok |
| **dark** | Uygulama internete **hiç** çıkmasın | Kenar → overlay → uygulama | **Gelen kural YOK**, yalnız giden |

### Uygulama sahibi ne yapar

**Hiçbir şey.** Kod değişmez, kütüphane eklenmez, ajan kurulmaz. Uygulama yalnızca kendi makinesinde (loopback veya iç ağ) dinlemeye devam eder.

Değişen tek şey: makinede **dışarıya açık port kalmaz**. Erişim overlay üzerinden gelir.

### Canlı kanıt (bu ortamda çalıştırıldı)

Bir test uygulaması yalnızca `127.0.0.1` üzerinde dinletildi, dışarıdan erişimi kapalı tutuldu:

| Kanıt | Sonuç |
|---|---|
| Uygulama dışarıdan doğrudan erişilebilir mi? | **Hayır** (bağlantı kapalı) |
| Uygulamada kod değişikliği | **Yok** |
| Yetkili kimlik overlay üzerinden | **200 — içerik geldi** |
| **Yetkisiz kimlik** | **"service not found"** — servisi göremiyor bile |

Son satır önemli: yetkisiz kullanıcı "erişim reddedildi" bile almıyor, **servisin varlığından haberdar olmuyor**. Keşif yüzeyi sıfır.

### Bulunan operasyonel tuzak

Yeni bir servis tanımlandığında ağ geçidi onu **hemen** üstlenmeyebiliyor; yeniden başlatılana kadar "terminatör yok" hatası alındı. Bu, "yapılandırma doğru ama servis çalışmıyor" gibi görünen sinsi bir durum.

**İyi haber:** yönetim arayüzündeki *"Perde arkası"* özelliği bu adımı zaten kontrol ediyor (6. adım: *"Bir ağ geçidi şu anda bağlı"*). Yani sorun görünür ve teşhis edilebilir.

---

## 5. Bulut ve ölçek

| Ortam | Durum |
|---|---|
| AWS | Terraform modülleri mevcut (ağ, veritabanı, önbellek, overlay) |
| Azure | **Modül yok** — eklenmesi gereken parça |
| Kubernetes | Ingress seviyesinde geçiş; tek uygulamayı taşımak da geri almak da tek kural |

**Yatay ölçek için ön koşul hazır:** oturum durumu paylaşılan önbellekte tutuluyor (Sentinel yapılandırması mevcut), yani ikinci düğüm eklemek durum kaybı yaratmaz.

**En riskli nokta ve dürüst beyan:** iki kontrol düzlemi düğümü aynı anda kenar yapılandırmasını yazarsa çakışma olabilir. Bu senaryo **henüz test edilmedi**; çok düğümlü kuruluma geçmeden önce ya idempotent yazım + kuşak damgası ya da lider seçimi gerekir. Bunu "çalışıyor" diye işaretlemek yanlış olurdu.

---

## 6. Özet: hangi soruya ne cevap

| Soru | Cevap | Durum |
|---|---|---|
| Yük dengeleyici olabilir mi? | **Evet** — ağırlıklı çoklu arka uç, sağlık kontrolü, yapışkanlık | Canlı kanıtlandı (0 kayıp devre dışı bırakma) |
| Cloudflare gibi olabilir mi? | **Kısmen ve bilinçli olarak.** Kimlik-farkında uygulama kenarı evet; CDN/anycast **hayır** | Kapsam kararı, §1-K3 |
| Azure'da koşar mı? | **Evet**, ama Azure modülü yazılmalı | AWS hazır, Azure eksik |
| İç sistemler kapatılabilir mi? | **Evet** — gelen port açmadan | Canlı kanıtlandı |
| Uygulamalar nasıl entegre olur? | **Değişmeden.** Kod yok, ajan yok; tek soru "nerede çalışıyor" | Canlı kanıtlandı |

---

## 7. Sıradaki adımlar

1. **Azure Terraform modülü** (tek eksik bulut parçası)
2. **Çok düğümlü uzlaştırıcı güvenliği** — çakışma testi ve koruma
3. **Otomatik sertifika yenileme** (bugün elle)
4. Havuz yönetimi için yönetim arayüzü ekranı
