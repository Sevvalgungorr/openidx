# OpenIDX — E-İhracat Başvuru Sunumu

Bu klasör, e-ihracat destek başvurusu için hazırlanan tanıtım sunumunu içerir.

## Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `OpenIDX-E-Ihracat-Sunum-TR.pdf` | **Teslim edilecek sunum (PDF)** — 10 slayt, 16:9 |
| `OpenIDX-E-Ihracat-Sunum-TR.pptx` | Düzenlenebilir PowerPoint sürümü (aynı içerik) |
| `OpenIDX-E-Ihracat-Sunum-TR.html` | Kaynak (tarayıcıda açılır, PDF bundan üretildi) |
| `build_pptx.py` | PPTX üretim betiği (python-pptx) |

Başvuruda **PDF veya PPTX** kabul edildiği için ikisi de hazır; PDF'i göndermeniz yeterlidir.

## İstenen bölümlerin slaytlarla eşleşmesi

Başvuru talebinde istenen beş başlık sunumda ayrı bölümler olarak işlenmiştir:

| İstenen başlık | Slayt |
|----------------|-------|
| Projenin e-ihracatla ilişkisi | **Bölüm 1 — Slayt 3** |
| Sunulan ürün veya hizmet | **Bölüm 2 — Slayt 4** (+ moat: Slayt 5) |
| Hedef pazarlar | **Bölüm 3 — Slayt 6** (+ fiyat konumu: Slayt 7) |
| Mevcut gelişim aşaması | **Bölüm 4 — Slayt 8** |
| Global büyüme hedefleri | **Bölüm 5 — Slayt 9** |

Slayt 1 kapak, Slayt 2 yönetici özeti, Slayt 10 kapanıştır.

## Konumlandırma notu

Sunum, olgunluk seviyesini **"MVP–Erken GA"** olarak şeffaf konumlandırır
(abartısız). Fiyat, pazar ve rakip iddiaları repo içi kod-doğrulanmış
analizlere ve 2026 pazar araştırmasına dayanır.

## Yeniden üretim

PDF'i HTML'den yeniden üretmek için:

```bash
google-chrome --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=OpenIDX-E-Ihracat-Sunum-TR.pdf OpenIDX-E-Ihracat-Sunum-TR.html
```

PPTX'i yeniden üretmek için:

```bash
python3 build_pptx.py
```
