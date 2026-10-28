//! The app's privacy policy — `GET /gizlilik` (Turkish) and `GET /privacy` (English).
//!
//! Google Play needs the policy at a public URL, and Hasan chose his own server's address for it
//! (2026-10-28): `https://zh.revisetouch.work/gizlilik`. It is the APP's policy, not a server's,
//! so every relay serves the same page; the source text is `docs/play/PRIVACY_POLICY.md` and the
//! two must change together.
//!
//! LANGUAGE: like `welcome.rs`, this is a product surface served straight to a browser, never
//! source language — the Turkish here is exempt from the English-source rule.
//!
//! Self-contained: inline CSS, no external resource, the welcome page's palette.

use worker::*;

/// `GET /gizlilik`.
pub async fn gizlilik(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    page(Policy::Tr)
}

/// `GET /privacy`.
pub async fn privacy(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    page(Policy::En)
}

#[derive(Clone, Copy)]
enum Policy {
    Tr,
    En,
}

fn page(policy: Policy) -> Result<Response> {
    let mut resp = Response::from_html(render(policy))?;
    resp.headers_mut().set("Cache-Control", "public, max-age=3600")?;
    Ok(resp)
}

fn render(policy: Policy) -> String {
    let (lang, title, other, body) = match policy {
        Policy::Tr => ("tr", "Sezi — Gizlilik Politikası", OTHER_TR, BODY_TR),
        Policy::En => ("en", "Sezi — Privacy Policy", OTHER_EN, BODY_EN),
    };
    format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{title}</title><style>{STYLE}</style></head>\
         <body><main class=\"card\"><p class=\"other\">{other}</p><h1>{title}</h1>\
         <p class=\"meta\">{UPDATED}</p>{body}</main></body></html>"
    )
}

const UPDATED: &str = "2026-10-28";

const OTHER_TR: &str = "<a href=\"/privacy\">English</a>";
const OTHER_EN: &str = "<a href=\"/gizlilik\">Türkçe</a>";

const STYLE: &str = r#"
:root { --page:#F1E6D4; --paper:#FAF1E6; --ink:#201812; --ink-soft:#6F6357; --rule:#E7DAC6; --accent:#EA580C; }
@media (prefers-color-scheme: dark) {
  :root { --page:#16100B; --paper:#1D1610; --ink:#F1E9DE; --ink-soft:#A79B8D; --rule:#3A2F24; --accent:#FB923C; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--page); color:var(--ink); padding:24px 16px;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.card { background:var(--paper); border:1px solid var(--rule); border-radius:18px;
  max-width:720px; margin:0 auto; padding:32px 28px; }
h1 { font-size:24px; margin:0 0 4px; letter-spacing:-.2px; }
h2 { font-size:17px; margin:26px 0 8px; }
p, li { font-size:15px; line-height:1.6; color:var(--ink-soft); }
p b, li b { color:var(--ink); }
ul { padding-left:20px; }
a { color:var(--accent); }
.meta { margin-top:0; font-size:13px; }
.other { float:right; margin:0; font-size:14px; }
"#;

const BODY_TR: &str = r#"
<p>Sezi, birbirini tanıyan küçük topluluklar için uçtan uca şifreli bir mesajlaşma ve uygulama platformudur. Bu politika Sezi Android uygulamasının hangi verileri işlediğini anlatır.</p>
<p><b>Geliştirici:</b> Hasan Salihoğlu · <b>İletişim:</b> <a href="mailto:hsn.salihoglu@gmail.com">hsn.salihoglu@gmail.com</a></p>
<h2>Sunucular kimin?</h2>
<p>Sezi'yi bir sunucuya katılarak kullanırsınız. Sunucuyu, sizi davet eden kişi ya da kurum işletir; Sezi'nin geliştiricisi her sunucunun işletmecisi değildir. Sunucu işletmecisi mesajlarınızı okuyamaz (aşağıya bakın), ancak "Sunucunun gördükleri" başlığındaki bilgileri görebilir.</p>
<h2>Uçtan uca şifreleme</h2>
<p>Mesajlarınız, gönderdiğiniz dosyalar, sesli mesajlar ve aramalar cihazınızda şifrelenir ve yalnızca alıcıların cihazlarında çözülür. Şifreleme anahtarları cihazınızdan çıkmaz. Sunucu şifreli içeriği yalnızca teslim edilene kadar (dosyalarda sunucunun saklama süresi boyunca) tutar ve içeriği okuyamaz.</p>
<h2>Sunucunun gördükleri</h2>
<ul>
<li>Görünen adınız ve profil fotoğrafınızın şifreli kopyası,</li>
<li>kimlerle aynı sohbette ya da grupta olduğunuz, mesajların ne zaman gönderildiği ve boyutları,</li>
<li>bağlantı sırasında IP adresiniz,</li>
<li>bildirim almak için cihazınızın bildirim belirteci (push token).</li>
</ul>
<h2>Bildirimler (Google Firebase Cloud Messaging)</h2>
<p>Uygulama kapalıyken yeni mesajlardan haberdar olmanız için sunucu, Google'ın FCM hizmeti üzerinden cihazınızı uyandırır. Bu uyandırma mesajı içerik taşımaz; mesaj cihazınızda indirilip çözülür. Google, bildirimi iletmek için cihaz belirtecini ve uyandırmanın zamanını işler.</p>
<h2>İzinler ve ne için kullanıldıkları</h2>
<ul>
<li><b>Kamera:</b> fotoğraf, video, görüntülü arama, QR kod okuma.</li>
<li><b>Mikrofon:</b> sesli mesaj ve aramalar.</li>
<li><b>Konum:</b> yalnızca bir sohbette konumunuzu paylaşmayı seçtiğinizde, o an bir kez okunur.</li>
<li><b>Bildirimler:</b> mesaj ve arama bildirimleri.</li>
<li><b>Ekran paylaşımı:</b> yalnızca bir aramada ekranınızı paylaşmayı seçtiğinizde.</li>
<li><b>Biyometri:</b> uygulama kilidi; parmak izi ya da yüz verisi cihazdan çıkmaz.</li>
</ul>
<h2>Sizin seçtiğiniz üçüncü taraf hizmetler</h2>
<p>Aşağıdakiler yalnızca siz açar ve kendi hesabınızı ya da anahtarınızı girerseniz çalışır; ilgili metin doğrudan sizin seçtiğiniz hizmete gider ve o hizmetin gizlilik politikasına tabidir: yapay zekâ hizmeti (ör. Anthropic, OpenAI), çeviri hizmeti (Google Cloud Translation, DeepL ya da kendi LibreTranslate sunucunuz), uygulama içinde açılan web siteleri (ör. destepdf.com) ve gömülü YouTube oynatıcısı (youtube-nocookie.com).</p>
<p>Grup aramaları kalabalıksa Cloudflare'in medya sunucusu (SFU) üzerinden geçebilir; ses ve görüntü kareleri bu durumda da uçtan uca şifrelidir.</p>
<h2>Toplamadıklarımız</h2>
<p>Reklam yok, analitik ya da izleme aracı yok, kişi listenize erişim yok; verileriniz satılmaz ve reklam amacıyla paylaşılmaz. Hata raporları otomatik gönderilmez.</p>
<h2>Yedekler</h2>
<p>Bir yedek oluşturursanız, yedek kendi anahtarınızla şifrelenir ve yalnızca sizin seçtiğiniz yere kaydedilir.</p>
<h2>Saklama ve silme</h2>
<p>Teslim edilen mesajlar sunucudan silinir. Bir sunucudan ayrıldığınızda o sunucudaki hesabınız ve cihazınızdaki o sunucuya ait veriler silinir. Uygulamayı kaldırmak cihazdaki tüm verileri siler. Silme talepleri için sunucunuzun işletmecisine ya da yukarıdaki adrese yazabilirsiniz.</p>
<h2>Çocuklar</h2>
<p>Sezi 13 yaşından küçükler için tasarlanmamıştır.</p>
<h2>Değişiklikler</h2>
<p>Bu politika değişirse güncel hali bu adreste yayımlanır.</p>
"#;

const BODY_EN: &str = r#"
<p>Sezi is an end-to-end encrypted messaging and app platform for small communities whose members know each other. This policy describes what data the Sezi Android app handles.</p>
<p><b>Developer:</b> Hasan Salihoğlu · <b>Contact:</b> <a href="mailto:hsn.salihoglu@gmail.com">hsn.salihoglu@gmail.com</a></p>
<h2>Whose servers?</h2>
<p>You use Sezi by joining a server, run by the person or organisation that invited you; the developer of Sezi does not operate every server. A server's operator cannot read your messages (see below) but can see the items listed under "What the server sees".</p>
<h2>End-to-end encryption</h2>
<p>Your messages, files, voice notes and calls are encrypted on your device and decrypted only on the recipients' devices. Encryption keys never leave your device. The server holds encrypted content only until it is delivered (files: for the server's retention period) and cannot read it.</p>
<h2>What the server sees</h2>
<ul>
<li>your display name and an encrypted copy of your profile photo,</li>
<li>who shares a conversation or group with whom, when messages are sent and their sizes,</li>
<li>your IP address while connected,</li>
<li>your device's push token, to wake it for new messages.</li>
</ul>
<h2>Notifications (Google Firebase Cloud Messaging)</h2>
<p>To tell you about new messages while the app is closed, the server wakes your device through Google's FCM. The wake-up carries no message content; the message is fetched and decrypted on your device. Google processes the device token and the time of the wake-up to deliver it.</p>
<h2>Permissions and what they are for</h2>
<ul>
<li><b>Camera:</b> photos, video, video calls, scanning QR codes.</li>
<li><b>Microphone:</b> voice notes and calls.</li>
<li><b>Location:</b> read once, only when you choose to share your location in a conversation.</li>
<li><b>Notifications:</b> message and call notifications.</li>
<li><b>Screen sharing:</b> only when you choose to share your screen in a call.</li>
<li><b>Biometrics:</b> the app lock; fingerprint or face data never leaves the device.</li>
</ul>
<h2>Third-party services you choose</h2>
<p>These work only if you turn them on and enter your own account or key; the text involved goes directly to the service you chose and is subject to its privacy policy: an AI service (e.g. Anthropic, OpenAI), a translation service (Google Cloud Translation, DeepL or your own LibreTranslate server), websites opened inside the app (e.g. destepdf.com) and the embedded YouTube player (youtube-nocookie.com).</p>
<p>A crowded group call may go through Cloudflare's media server (SFU); its audio and video frames stay end-to-end encrypted.</p>
<h2>What we do not collect</h2>
<p>No ads, no analytics or tracking tools, no access to your contacts; your data is not sold or shared for advertising. Crash reports are not sent automatically.</p>
<h2>Backups</h2>
<p>A backup you create is encrypted with your own key and saved only where you choose.</p>
<h2>Retention and deletion</h2>
<p>Delivered messages are deleted from the server. Leaving a server deletes your account there and that server's data on your device. Uninstalling the app deletes all data on the device. For deletion requests, write to your server's operator or to the address above.</p>
<h2>Children</h2>
<p>Sezi is not designed for children under 13.</p>
<h2>Changes</h2>
<p>If this policy changes, the current version is published at this address.</p>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_page_is_its_language_and_links_the_other() {
        let tr = render(Policy::Tr);
        assert!(tr.contains("<html lang=\"tr\">") && tr.contains("Gizlilik Politikası"));
        assert!(tr.contains("href=\"/privacy\""));
        let en = render(Policy::En);
        assert!(en.contains("<html lang=\"en\">") && en.contains("Privacy Policy"));
        assert!(en.contains("href=\"/gizlilik\""));
    }

    #[test]
    fn no_placeholder_is_left_and_the_contact_is_there() {
        for page in [render(Policy::Tr), render(Policy::En)] {
            assert!(!page.contains('['), "a [PLACEHOLDER] is still in the page");
            assert!(page.contains("mailto:hsn.salihoglu@gmail.com"));
        }
    }

    /// The page says the wake push carries no content; `push/fcm.rs` is what makes that true.
    #[test]
    fn the_claim_about_wake_pushes_matches_the_sender() {
        let fcm = include_str!("push/fcm.rs");
        assert!(fcm.contains("CONTENTLESS wake push"));
    }
}
