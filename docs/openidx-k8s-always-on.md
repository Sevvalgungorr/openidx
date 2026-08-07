# Kubernetes Always-On: Ne Kanıtlandı, Ne Kanıtlanmadı

Bu belge, OpenIDX'in Kubernetes üzerinde "her zaman açık" çalışması için yapılanları ve **hâlâ kanıtlanmamış olanı** kayda geçirir. Kanıtlanmamış olanı gizlemek, bir kesinti anında en pahalı hatadır.

---

## 1. Zaten yerinde olanlar (ölçüldü, dokunulmadı)

Chart bu çalışmaya başlarken sanılandan çok daha olgundu:

| Alan | Durum |
|---|---|
| Replika | Servis başına 2–3, HPA ile 6–12'ye kadar |
| Kesinti bütçesi | PodDisruptionBudget tanımlı |
| Düğüm dağılımı | podAntiAffinity (aynı düğüme yığılmayı önler) |
| Sağlık | liveness + readiness prob'ları |
| Sırlar | ExternalSecrets (küme içinde düz sır yok) |
| Ağ | NetworkPolicy ile bölümleme |
| Veri katmanı | Yönetilen hizmetler; küme içi veritabanı kapalı |
| Overlay | Ziti controller StatefulSet, Raft'a hazır |
| Uygulama | Zarif kapanma (drain) uygulanmış |
| Tatbikat | `make ha-drill` ve `make dr-game-day`, mutasyon testli |

**Bu yüzden chart yeniden yazılmadı.** Çalışan bir HA kurgusunu elden geçirmek yeni risk üretir.

---

## 2. Kapatılan boşluklar

### 2.1 Dağıtım sırasındaki istek kaybı

Kubernetes bir Pod'u servis listesinden çıkarmakla kapanma sinyali göndermeyi **aynı anda** yapar ve bu iki iş küme genelinde bağımsız yayılır. Uygulama doğru kapansa bile, sinyali alır almaz kapanırsa bazı düğümler hâlâ ona istek yönlendiriyor olabilir.

**Sağlıklı bir güncelleme sırasında görülen 502'lerin olağan sebebi budur.**

Eklenen: kısa bir bekleme (`preStop`) ve bunu kapsayan bir kapanma süresi. Bekleme hiçbir iş yapmaz; sadece "beni listeden çıkarın" işleminin yarışı kazanmasını sağlar.

### 2.2 Güncelleme sırasında kapasite düşmesi

Kubernetes varsayılanı, yedek hazır olmadan filonun dörtte birini servisten alabilir. Artık **yeni kopya hazır olmadan eskisi gitmiyor**; kapasite hiç düşmüyor. Bedeli, güncelleme süresince bir kopyalık ek kaynak.

### 2.3 Bölge (AZ) kaybı

Düğüm dağılımı bir sunucunun ölmesine dayanır, ama tüm kopyaların aynı **bölgeye** düşmesini engellemez. Bir bölge kaybı tüm servisi götürürdü. Artık kopyalar bölgelere yayılıyor.

Yayılım **zorlayıcı değil**: tek bölgeli bir kümede zorlayıcı kural kopyaları başlatılamaz hâle getirir ve erişilebilirlik kazanımını kesintiyle takas ederdi.

### 2.4 Overlay tek nokta

Overlay, iç uygulamaların **güvenlik duvarında gelen kural açmadan** yayınlanmasını sağlayan katman. Üretimde açıldı ve yedekli boyutlandırıldı:

- **Kontrol düzlemi 3 kopya.** Çoğunluk gerektiği için 1 tek noktadır; **2 ise 1'den kötüdür** (tek kayıp kilitler).
- **Veri düzlemi 2 kopya.** Tek yönlendiriciyle onu kaybetmek **tüm kapalı uygulamaları aynı anda** düşürür.

### 2.5 Tatbikat

`make k8s-chaos`. İki mod:

- **Statik:** küme gerektirmez, CI'da koşar. Zarif kapanma, bölge yayılımı, kapasite koruyan güncelleme veya kesinti bütçesi olmadan dağıtılacak bir bileşen varsa **başarısız olur**. Ayrıca manifest'i **gerçek Kubernetes şemasına** karşı doğrular.
- **Canlı:** gerçek kopya öldürme, güncelleme, düğüm boşaltma ve overlay yönlendirici kaybını **sürekli istek göndererek** çalıştırır ve **gerçekten kaybolan istek sayısını** raporlar.

---

## 3. Tatbikatın kendisi test edildi

Bir tatbikat yanlış yeşil verirse, hiç olmamasından kötüdür: güven verir.

İlk yazımda şema doğrulaması **bozuk bir manifest'te bile yeşil veriyordu**. Üç sebep vardı:

1. Doğrulayıcı uzantısız dosyaları **atlıyordu**; "0 kaynak bulundu" sonucu "hiçbiri geçersiz" diye okunuyordu.
2. Başarı ölçütü `Invalid: 0` metnini arıyordu; bu **`Invalid: 10`** içinde de geçer.
3. Sıfır kaynak başarı sayılıyordu; oysa boş çıktı "chart hiç dağıtılamaz" demektir.

Üçü de düzeltildi ve **mutasyonla** doğrulandı: bir alan adı kasten bozulduğunda tatbikat kırmızıya döndü (geçersiz: 1), düzeltilince 51 kaynak doğrulandı.

---

## 4. Kanıtlanmayan: canlı küme testi

**Bu makinede gerçek bir küme kurulamadı.** Denendi ve neden başarısız olduğu kayda geçti:

| Araç | Engel |
|---|---|
| kind | Konteyner ortamı beklenen sistem hedefine ulaşmıyor (cgroup v2 + rootless) |
| k3d | Konteyner soketine erişim izni yok |

**Sonuç:** bu çalışmadaki tüm kanıtlar **manifest düzeyindedir**. Statik denetim ve şema doğrulaması niyeti ve geçerliliği kanıtlar, **dayanıklılığı kanıtlamaz**.

Gerçek kanıt için bir kümede şu çalıştırılmalı:

```
scripts/k8s-chaos-drill.sh --namespace <ad> --url https://<api-adresi>
```

Bu, kopyaları öldürüp düğüm boşaltırken **gerçekten kaybolan istek sayısını** ölçer. O sayı sıfır çıkana kadar "istek kaybı yok" **iddia edilmemelidir**.

---

## 5. Kalan işler

| Konu | Durum |
|---|---|
| Canlı kaos testi | **Küme bekliyor** (yukarıdaki komut hazır) |
| Bölge yayılımının gerçek etkisi | Çok bölgeli kümede ölçülmeli |
| Azure altyapı modülü | Yok (AWS mevcut) |
| Otomatik sertifika yenileme | Elle |
| Uyarıların gerçekten ulaşması | Kural var, teslim yolu doğrulanmadı |

---

## 6. Özet

| Soru | Cevap |
|---|---|
| Güncelleme sırasında istek kaybı olur mu? | Manifest artık kaybı önleyecek şekilde; **canlı ölçüm bekliyor** |
| Bir sunucu ölürse? | Kopyalar farklı sunucularda, kesinti bütçesi korur |
| Bir bölge ölürse? | Kopyalar bölgelere yayılıyor; **çok bölgeli kümede doğrulanmalı** |
| Overlay ölürse? | Kontrol düzlemi 3, veri düzlemi 2 kopya |
| Bunu nasıl bilebilirim? | `make k8s-chaos`, ve kümede canlı mod |
