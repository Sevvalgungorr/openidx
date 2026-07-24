# OpenIDX — Uçtan Uca Özellik Test Rehberi

> Canlı ortam: **https://openidx.tdv.org**
> Bu rehber, uygulamanın tüm ana özelliklerini **mantıklı bir sırayla** test etmen için hazırlandı. Her adımda **ne yapacağın**, **ne görmen gerektiği** (başarı kriteri) ve gerekli **ön koşul** yazılı.
> `securetask` uygulaması ve onunla oturum açan test kullanıcısı bu rehberin 4. bölümünde doğrulanıyor.

Kullanım: Her satırın başındaki `[ ]` kutusunu test ettikçe `[x]` yap. Bir özellik çalışmazsa "Not" sütununa yaz.

---

## 0. Ön Hazırlık (5 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 0.1 | `https://openidx.tdv.org` adresine git | Login sayfası açılır (mavi kalkan logo, "Sign in with OpenIDX") | [ ] |
| 0.2 | Admin hesabıyla giriş yap | Dashboard açılır, sol menü görünür | [ ] |
| 0.3 | Sol menüde 8 ana grup gör: Home, IAM, Zero Trust Network, PAM, Audit, Analytics, AI, Platform | Tüm gruplar açılıp kapanıyor | [ ] |
| 0.4 | Sağ üstte org/tenant seçiciyi kontrol et | Aktif organizasyon görünür | [ ] |

---

## 1. Kimlik & Kullanıcı Yönetimi (IAM) — Temel (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 1.1 | **Users** (`/users`) → yeni kullanıcı ekle | Kullanıcı listede görünür, e-posta + geçici parola | [ ] |
| 1.2 | **Groups** (`/groups`) → grup oluştur, kullanıcıyı ekle | Kullanıcı grup üyeliğinde görünür | [ ] |
| 1.3 | **Roles** (`/roles`) → role bak, gruba/kullanıcıya ata | Rol ataması kaydedilir | [ ] |
| 1.4 | **Service Accounts** (`/service-accounts`) → makine hesabı + API anahtarı üret | Client ID/secret üretilir | [ ] |
| 1.5 | **Directories** (`/directories`) → LDAP/AD bağlayıcı ekranını aç | Bağlayıcı tipi seçilebilir (test bağlantısı opsiyonel) | [ ] |
| 1.6 | **Bulk Operations** (`/bulk-operations`) → CSV ile içe/dışa aktarımı aç | Import/export ekranı açılır | [ ] |

---

## 2. Güvenlik & MFA (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 2.1 | **MFA Management** (`/mfa-management`) → bir kullanıcının faktörlerini gör | TOTP/kayıtlı faktörler listelenir, sıfırlama var | [ ] |
| 2.2 | **Passwordless** (`/passwordless-settings`) → magic-link'i aç | Ayar kaydedilir *(magic-link e-postası artık gerçekten gönderiliyor — PR #513)* | [ ] |
| 2.3 | **Security Keys** (`/security-keys`) → WebAuthn/passkey kaydını dene | Passkey kayıt akışı başlar | [ ] |
| 2.4 | **Push Devices** (`/push-devices`) → mobil push cihazlarını gör | Kayıtlı cihazlar *(FCM v1 + APNS artık gerçek delivery — PR #513)* | [ ] |
| 2.5 | **Hardware Tokens** (`/hardware-tokens`) → YubiKey/OTP ekle | Token kaydı ekranı | [ ] |
| 2.6 | **Risk Policies** (`/risk-policies`) → adaptif/koşullu erişim kuralı gör | Kural editörü açılır | [ ] |
| 2.7 | **Login Anomalies** (`/login-anomalies`) → şüpheli girişler | "Impossible travel" vb. anomali listesi | [ ] |
| 2.8 | **MFA Bypass Codes** (`/mfa-bypass-codes`) → kurtarma kodları üret | Yedek kodlar üretilir | [ ] |

---

## 3. Uygulamalar & Federasyon (SSO) (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 3.1 | **Applications** (`/applications`) → listeyi gör | `securetask` dahil 9 uygulama görünür | [ ] |
| 3.2 | Yeni OIDC uygulaması ekle (redirect URI ver) | Client ID + secret üretilir | [ ] |
| 3.3 | Uygulama detayında **"Require consent"** seçeneğini aç | Ayar kaydedilir *(consent artık gerçekten zorlanıyor — PR #513)* | [ ] |
| 3.4 | **Identity Providers** (`/identity-providers`) → OIDC/SAML IdP ekle | IdP config ekranı | [ ] |
| 3.5 | **SAML Providers** (`/saml-service-providers`) → SP ekle, metadata indir | Metadata XML iner *(imzalama artık goxmldsig ile standart — PR #513)* | [ ] |
| 3.6 | **Social Providers** (`/social-providers`) → Google/GitHub bağla | Sosyal giriş config | [ ] |
| 3.7 | **Provisioning Rules** (`/provisioning-rules`) → SCIM/sync kuralı | Kural editörü | [ ] |
| 3.8 | **Lifecycle Workflows** (`/lifecycle-workflows`) → joiner/mover/leaver | İş akışı tanımlanabilir | [ ] |

---

## 4. ⭐ securetask SENARYOSU — Uçtan Uca SSO Login (senin testin)

Bu, senin yaptığın testin doğrulanmış hali. `securetask` = OIDC web uygulaması, redirect `http://localhost:8000/callback`.

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 4.1 | **Applications** → `securetask`'i aç, config'i doğrula | protocol=openid-connect, redirect=`http://localhost:8000/callback` | [ ] |
| 4.2 | `securetask` uygulamasını başlat (kendi callback'i localhost:8000) | Uygulama OpenIDX'e yönlendirir | [ ] |
| 4.3 | OpenIDX login ekranında test kullanıcısı ile giriş | Kimlik doğrulanır | [ ] |
| 4.4 | (Consent açıksa) onay ekranı gelir → **Allow** | Kapsam onayı kaydedilir, tekrar girişte sorulmaz | [ ] |
| 4.5 | `securetask`'e geri yönlendirilirsin, oturum açık | Uygulama içinde kullanıcı bilgisi görünür | [ ] |
| 4.6 | **Sessions** (`/sessions`) → aktif oturumu gör | securetask oturumu listede | [ ] |
| 4.7 | **My Apps** (`/app-launcher`) → kullanıcı portalında securetask ikonu | Tek tıkla tekrar giriş yapılabilir | [ ] |
| 4.8 | Sessions'tan oturumu **revoke** et | securetask'te oturum düşer | [ ] |

---

## 5. Governance / Yönetişim (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 5.1 | **Policies** (`/policies`) → OPA politikası gör | Rego kural editörü | [ ] |
| 5.2 | **Approval Policies** (`/approval-policies`) → onay akışı tanımla | Approver zinciri kaydedilir | [ ] |
| 5.3 | **Access Requests** (`/access-requests`) → erişim talebi oluştur | Talep onay akışına düşer | [ ] |
| 5.4 | **Access Reviews** (`/access-reviews`) → recertification kampanyası | Kampanya oluşturulur | [ ] |
| 5.5 | **Entitlements** (`/entitlements`) → yetki kataloğu | Grant listesi | [ ] |
| 5.6 | **ABAC Policies** (`/abac-policies`) → öznitelik bazlı kural | Kural editörü | [ ] |
| 5.7 | **Delegations** (`/delegations`) → admin yetkisi devret | Devir kaydı | [ ] |
| 5.8 | **Consent Mgmt** (`/consent-management`) → GDPR onayları | Onay kayıtları | [ ] |

---

## 6. Zero Trust Network (Ziti) — ⭐ Ana Farklılaştırıcı (15 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 6.1 | **Zero Trust Access** (`/zero-trust`) → yayınlanmış servisleri gör | openidx-access dahil servis listesi | [ ] |
| 6.2 | **Ziti Network** (`/ziti-network`) → identity + edge router listesi | Controller online, router online | [ ] |
| 6.3 | **App Publish** (`/app-publish`) → bir iç uygulamayı overlay'e yayınla | Servis + policy oluşturulur | [ ] |
| 6.4 | **Proxy Routes** (`/proxy-routes`) → reverse-proxy vhost kuralları | Route listesi | [ ] |
| 6.5 | **BrowZer** (`/browzer-management`) → clientless tarayıcı erişimi | BrowZer config | [ ] |
| 6.6 | **Certificates** (`/certificates`) → TLS/PKI/CA | Sertifika listesi | [ ] |
| 6.7 | **Agent Fleet** (`/agent-fleet`) → kayıtlı cihaz agent'ları | Windows agent'lar (CMIT0601L-025 online) | [ ] |
| 6.8 | **Devices** (`/devices`) → cihaz posture durumu | Cihaz sağlık/uyumluluk | [ ] |
| 6.9 | ⭐ **Remote Support** (`/remote-support`) → oturum başlat | Aşağıdaki 6.10 akışı | [ ] |
| 6.10 | Remote Support: cihaz seç → **Connection: Zero-trust relay** → başlat | Ekran paylaşımı + kontrol overlay üzerinden akar; "Zero-trust relay" rozeti | [ ] |
| 6.11 | Remote Support: **Pop out** ve **Fullscreen** dene | Ayrı pencere + tam ekran çalışır | [ ] |

---

## 7. Privileged Access (PAM) (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 7.1 | **PAM Dashboard** (`/pam-dashboard`) → özet | Privileged erişim özeti | [ ] |
| 7.2 | **Vault Secrets** (`/vault-secrets`) → gizli bilgi ekle | Şifreli secret kaydedilir | [ ] |
| 7.3 | **Connections** (`/pam-connections`) → RDP/SSH/VNC bağlantısı tanımla | Bağlantı kartı | [ ] |
| 7.4 | **My Privileged Access** (`/my-privileged-access`) → checkout | Secret checkout + süreli erişim | [ ] |
| 7.5 | **Rotation Policies** (`/rotation-policies`) → parola rotasyon kuralı | 6 connector tipi seçilebilir | [ ] |
| 7.6 | **Privileged Sessions** (`/guacamole-sessions`) → oturum kaydı | Kayıtlı/aktif oturumlar | [ ] |

---

## 8. Denetim & Analitik (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 8.1 | **Audit Logs** (`/audit-logs`) → olayları filtrele | Zaman/aktör/aksiyon filtreleri | [ ] |
| 8.2 | **Live Audit Stream** (`/audit/dashboard`) → canlı akış | Yeni olaylar gerçek zamanlı düşer | [ ] |
| 8.3 | **Unified Audit** (`/unified-audit`) → birleşik görünüm | IAM+PAM+ağ olayları tek yerde | [ ] |
| 8.4 | **Login Analytics** (`/login-analytics`) → giriş grafikleri | Başarılı/başarısız giriş trendleri | [ ] |
| 8.5 | **Compliance** (`/compliance-reports`) → rapor üret | SOC2/ISO benzeri rapor çıktısı | [ ] |
| 8.6 | **Reports** (`/reports`) → dışa aktar | CSV/PDF indirilir | [ ] |
| 8.7 | **Risk Dashboard** (`/risk-dashboard`) → risk skorları | Kullanıcı/olay risk skorları | [ ] |

---

## 9. AI & İçgörüler (5 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 9.1 | **Security Posture** (`/ispm`) → duruş skoru | Genel güvenlik skoru + bulgular | [ ] |
| 9.2 | **Recommendations** (`/ai-recommendations`) → öneriler | Aksiyona dönüştürülebilir öneriler | [ ] |
| 9.3 | **AI Agents** (`/ai-agents`) → ajan kimlikleri | Agent identity listesi | [ ] |

---

## 10. Platform Yönetimi (10 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 10.1 | **Organizations** (`/organizations`) → org listesi (16 org) | Multi-tenant izolasyon | [ ] |
| 10.2 | **Tenant Mgmt** (`/tenant-management`) → tenant ayarları | Tenant yönetimi | [ ] |
| 10.3 | **Branding** (`/branding`) → logo/renk özelleştir | Login/portal görünümü değişir | [ ] |
| 10.4 | **Email Templates** (`/email-templates`) → şablon düzenle | Magic-link/davet şablonları | [ ] |
| 10.5 | **Webhooks** (`/webhooks`) → giden webhook ekle | HMAC imzalı webhook config | [ ] |
| 10.6 | **Settings** (`/settings`) → genel ayarlar | Platform ayarları | [ ] |

---

## 11. Geliştirici Araçları (5 dk)

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 11.1 | **API Explorer** (`/api-explorer`) → canlı API çağrısı | İstek/yanıt görünür | [ ] |
| 11.2 | **OAuth Playground** (`/oauth-playground`) → auth code akışı | Token alınır | [ ] |
| 11.3 | **API Docs** (`/api-docs`) → OpenAPI dökümantasyonu | Endpoint listesi | [ ] |
| 11.4 | **Developer Settings** (`/developer-settings`) → geliştirici ayarları | Feature flag/anahtarlar | [ ] |

---

## 12. Son Kullanıcı Portalı (kullanıcı gözünden — 5 dk)

> Admin'den çıkıp normal bir test kullanıcısıyla gir.

| # | Adım | Beklenen sonuç | Durum |
|---|------|----------------|-------|
| 12.1 | **My Profile** (`/profile`) → parola değiştir | Parola güncellenir | [ ] |
| 12.2 | **My Apps** (`/app-launcher`) → securetask'e tıkla | SSO ile giriş | [ ] |
| 12.3 | **My Access** (`/my-access`) → yetkilerimi gör | Entitlement listesi | [ ] |
| 12.4 | **My Devices** (`/my-devices`) → cihaz kaydı | Kayıtlı cihazlar | [ ] |
| 12.5 | **Access Requests** (`/access-requests`) → erişim talep et | Talep gönderilir | [ ] |
| 12.6 | **Notifications** (`/notification-center`) → bildirimler | Onay/uyarı bildirimleri | [ ] |

---

## Öncelik Sırası (zamanın kısıtlıysa)

1. **Bölüm 4** — securetask SSO (temel değer)
2. **Bölüm 6** — Zero Trust Network + Remote Support (ana farklılaştırıcı)
3. **Bölüm 1-3** — IAM + MFA + Apps (çekirdek)
4. **Bölüm 7** — PAM
5. **Bölüm 8** — Denetim (uyumluluk kanıtı)
6. Kalanlar

## PR #513 ile yeni düzelen özellikler (özellikle test et)
- ✅ Magic-link e-postası artık **gönderiliyor** (Bölüm 2.2)
- ✅ Push MFA **gerçek FCM v1 + APNS** delivery (Bölüm 2.4)
- ✅ OAuth **consent ekranı** artık zorlanıyor (Bölüm 3.3, 4.4)
- ✅ SAML imzalama **standart (goxmldsig)** (Bölüm 3.5)
- ✅ Güvenlik açığı: sahte `user-123` oturum yardımcısı **kaldırıldı**
