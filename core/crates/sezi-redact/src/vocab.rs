//! Word lists, all as matching keys ([`crate::fold::key`]: lowercase ASCII skeletons).
//!
//! The court vocabulary is the residual net's allow-list (§4.5) and the stop list of a body name
//! run (§4.4): a word on it is never taken for a name by those two. It does NOT protect a word
//! that a role label harvested as a name — "ADALET" the witness is masked everywhere, including in
//! "Adalet Bakanlığı" (over-masking is the safe error).

use std::collections::HashSet;
use std::sync::OnceLock;

/// Court and procedure vocabulary, matched whole.
const EXACT: &[&str] = &[
    // structure, header labels, function words
    "t", "c", "tc", "ve", "veya", "ile", "ya", "da", "de", "ki", "bu", "su", "o", "bir", "iki", "uc", "dort", "bes",
    "alti", "yedi", "sekiz", "dokuz", "on", "yirmi", "otuz", "kirk", "elli", "yuz", "bin", "ilk", "son", "no", "nu",
    "nolu", "nosu", "numara", "numarasi", "sayi", "sayili", "sayisi", "adi", "adres", "adresi", "tarih", "tarihi",
    "tarihli", "tarihinde", "saat", "saati", "gun", "gunu", "hafta", "ay", "yil", "sure", "kesin", "ara", "esas",
    "karar", "karari", "kararin", "kararina", "celse", "durusma", "hakim", "hakimi", "uye", "baskan", "baskani",
    "katip", "katibi", "zabit", "savci", "savcisi", "cumhuriyet", "davaci", "davacilar", "davali", "davalilar",
    "vekili", "vekilleri", "vekil", "dava", "davasi", "konu", "konusu", "suc", "sucu", "suclar", "sanik", "saniklar",
    "musteki", "mustekiler", "katilan", "katilanlar", "magdur", "magdurlar", "tanik", "taniklar", "tanigi",
    "bilirkisi", "tercuman", "ihbar", "olunan", "feri", "mudahil", "alacakli", "borclu", "muris", "velisi",
    "vasisi", "vasi", "kayyum", "mudafii", "mudafi", "supheli", "sikayetci", "asil", "asili", "taraf", "taraflar",
    "tarafindan", "avukat", "av", "stj", "dr", "prof", "doc", "sayin", "bay", "bayan", "bey", "hanim", "efendi", "isci", "isveren", "kurum",
    "sirket", "mudurlugu", "mudur", "genel", "bolge", "il", "ilce", "ili", "ilcesi", "nufus", "nufusa", "kayitli",
    "gereginin", "geregi", "gerekce", "gerekceli", "dusunuldu", "dair", "uyarinca", "geregince", "hukum", "hukmun",
    "kisa", "karar", "acik", "acikca", "okundu", "anlatildi", "usulen", "oybirligiyle", "oycoklugu", "oycokluguyla",
    "mahkemece", "mahkememiz", "mahkememizce", "tutanak", "tutanagi", "zapti", "zabti", "evrak", "dosya", "dosyasi",
    "tensip", "on", "inceleme", "tahkikat", "yargilama", "yargilamaya", "devam", "olundu", "edildi", "verildi",
    "sozlu", "yazili", "beyan", "beyani", "beyanlari", "savunma", "savunmasi", "mutalaa", "mutalaasi", "iddia",
    "iddianame", "sorgu", "sorgusu", "son", "soz", "sozu", "talep", "talebi", "istem", "istemi", "cevap", "replik",
    "duplik", "dilekce", "dilekcesi", "itiraz", "itirazi", "istinaf", "temyiz", "kanun", "kanunu", "madde",
    "maddesi", "maddesinin", "bent", "bendi", "fikra", "fikrasi", "yonetmelik", "teblig", "tebligat", "sonuc",
    "aciklama", "uyari", "not", "ek", "ekler", "delil", "deliller", "rapor", "raporu", "tespit", "kesif", "harc",
    "harci", "gider", "avansi", "masraf", "ucret", "ucreti", "vekalet", "tl", "ytl", "kr", "kurus", "lira", "usd",
    "eur", "euro", "avro", "dolar", "try", "gizli", "hazir", "gelmedi", "geldi", "yok", "var", "mevcut", "cn",
    "ogrenci", "cocuk", "cocuklar", "ortak", "musterek", "esi", "evlilik", "birlik", "birligi", "aile",
    "dogum", "dogumlu", "yeri", "istenen", "suruklenen", "suca", "vesayet", "kisitli", "karsi", "alicisi",
    "seri", "hesap", "hesabi", "numarali", "hat", "hatti", "plakali", "arac", "araci", "tasinmaz", "ada",
    "parsel", "bagimsiz", "bolum", "site", "yonetimi", "yonetici", "yoneticisi", "degisik",
    // statutes and institutions (abbreviations)
    "hmk", "tbk", "tmk", "tck", "cmk", "iik", "ttk", "humk", "bk", "mk", "ik", "isk", "sgk", "ssk", "uyap", "kvkk",
    "aym", "aihm", "aihs", "hsk", "hsyk", "bam", "bim", "cbs", "ctk", "kmk", "imar", "smmm", "ymm", "tbb", "pttk",
    "ptt", "cgtihk", "tmsf", "spk", "bddk", "noter", "baro", "barosu", "adli", "tip", "kurumu", "kurulu",
    "ataturk",
    // court types
    "asliye", "hukuk", "ceza", "agir", "sulh", "is", "ticaret", "tuketici", "icra", "iflas", "kadastro", "idare",
    "vergi", "fikri", "sinai", "haklar", "denizcilik", "infaz", "cocuk", "trafik", "mahkemesi", "mahkemesine",
    "mahkemesinin", "mahkemesince", "hakimligi", "dairesi", "dairesinin", "dairesine", "adliye", "adliyesi",
    // case subjects (dava türleri) and frequent minutes words
    "alacak", "alacagi", "alacaklar", "tazminat", "tazminati", "tazminatlari", "bosanma", "velayet", "nafaka",
    "istirak", "yoksulluk", "tedbir", "mal", "rejimi", "tasfiye", "tasfiyesi", "katki", "payi", "ise", "iade",
    "kidem", "fazla", "mesai", "yillik", "izin", "itirazin", "iptali", "iptal", "menfi", "musbet", "istirdat",
    "istihkak", "tapu", "tescil", "tescili", "kira", "tahliye", "tahliyesi", "ortakligin", "giderilmesi",
    "ecrimisil", "mudahalenin", "meni", "el", "atmanin", "onlenmesi", "kat", "mulkiyeti", "sozlesme",
    "sozlesmeden", "kaynaklanan", "maddi", "manevi", "kazasi", "kaza", "meslek", "hastaligi", "hizmet", "tespiti",
    "sigortalilik", "rucuan", "hakaret", "tehdit", "yaralama", "kasten", "taksirle", "hirsizlik", "dolandiricilik",
    "nitelikli", "guveni", "kotuye", "kullanma", "mala", "zarar", "verme", "uyusturucu", "uyarici", "ticareti",
    "konut", "dokunulmazligi", "dokunulmazliginin", "ihlali", "karsiliksiz", "cek", "cekin", "senet", "bono",
    "kambiyo", "takip", "takibi", "takibe", "haciz", "ihale", "ihalenin", "sikayet", "sikayeti", "imza", "imzaya",
    "itiraz", "borca", "borcun", "olmadiginin", "taksit", "faiz", "ticari", "temerrut", "asil", "fer", "ilami",
    "ilam", "ilamli", "ilamsiz", "kesinlesme", "kesinlesmis", "derdest", "birlestirme", "ayirma", "gonderme",
    "gorevsizlik", "yetkisizlik", "ret", "red", "reddi", "kabul", "kabulu", "kismen", "feragat", "sulh",
    "kovusturma", "kovusturmaya", "yer", "olmadigina", "hapis", "cezasi", "adli", "para", "erteleme",
    "aciklanmasinin", "geri", "birakilmasi", "hagb", "beraat", "mahkumiyet", "dusme", "dusmesine", "tutuklama",
    "tutuklu", "tutuksuz", "tahliye", "adli", "kontrol", "yakalama", "emri", "zorlama", "hapsi", "tazyik",
    "e", "imzali", "imzalidir", "imzalanmistir", "dogrulama", "kodu", "kod", "barkod", "sistemi", "bilisim",
    "ulusal", "yargi", "agi", "projesi", "belge", "belgesi", "evraki", "elektronik", "guvenli", "sertifika",
    // months and days
    "ocak", "subat", "mart", "nisan", "mayis", "haziran", "temmuz", "agustos", "eylul", "ekim", "kasim", "aralik",
    "pazartesi", "sali", "carsamba", "persembe", "cuma", "cumartesi", "pazar",
    // provinces (court cities are masked through the court header, not as names)
    "adana", "adiyaman", "afyonkarahisar", "afyon", "agri", "amasya", "ankara", "antalya", "artvin", "aydin",
    "balikesir", "bilecik", "bingol", "bitlis", "bolu", "burdur", "bursa", "canakkale", "cankiri", "corum",
    "denizli", "diyarbakir", "edirne", "elazig", "erzincan", "erzurum", "eskisehir", "gaziantep", "giresun",
    "gumushane", "hakkari", "hatay", "isparta", "mersin", "icel", "istanbul", "izmir", "kars", "kastamonu",
    "kayseri", "kirklareli", "kirsehir", "kocaeli", "konya", "kutahya", "malatya", "manisa", "kahramanmaras",
    "mardin", "mugla", "mus", "nevsehir", "nigde", "ordu", "rize", "sakarya", "samsun", "siirt", "sinop", "sivas",
    "tekirdag", "tokat", "trabzon", "tunceli", "sanliurfa", "usak", "van", "yozgat", "zonguldak", "aksaray",
    "bayburt", "karaman", "kirikkale", "batman", "sirnak", "bartin", "ardahan", "igdir", "yalova", "karabuk",
    "kilis", "osmaniye", "duzce", "turkiye", "turk", "anadolu", "bati", "dogu",
];

/// Court and procedure stems: a key starting with one of these is vocabulary ("mahkememizce",
/// "savcılığının", "bilirkişiler").
const STEMS: &[&str] = &[
    "mahkeme", "savcilig", "bassavcilig", "mudurlug", "bakanlig", "baskanlig", "belediye", "hakimlig", "noterlig",
    "valilig", "kaymakamlig", "komutanlig", "karakol", "hastane", "universite", "yargitay", "danistay",
    "cumhuriyet", "adliye", "durusma", "tutanag", "dilekce", "beyanin", "beyanlar", "bilirkisi", "davaci",
    "davali", "musteki", "katilan", "magdur", "supheli", "vekil", "avukat", "mudafi", "tebligat", "tebli",
    "kanunun", "maddesi", "kararin", "kararla", "gerekce", "itiraz", "istinaf", "temyiz", "dosyanin", "dosyaya",
    "dosyada", "dosyasi", "harcin", "masraf", "tazminat", "nafaka", "velayet", "bosanma", "taniklar", "tanigin",
    "taniginin", "sanigin", "saniklar", "kurumu", "kurulu", "sirketi", "hazine", "maliye", "emniyet", "jandarma",
    "sosyal", "guvenlik", "baro", "noter", "adalet", "ticaret", "sanayi", "odasi", "birligi", "bankasi", "banka",
    "kooperatif", "vakfi", "dernegi", "sendika", "bolge", "idare", "icra", "iflas", "tapu", "kadastro", "nufus",
    "vatandaslik", "sigorta", "isveren", "iscinin", "rapor", "tespit", "inceleme", "ihtar", "ihtarname",
    "sozlesme", "duzenleme", "yargilama", "hukuk", "hukum", "infaz", "ceza", "tutuk", "kovusturma",
    "sorusturma", "iddianame", "mutalaa", "savunma", "taahhut", "uyap", "elektronik", "muvekkil", "atanma",
    "aday", "kisitla", "vesayet", "tedbir", "sigortal", "teminat", "keside", "muhatap", "ihale", "satis",
    "muvazaa",
];

/// The roles a body anchor or a header label stands on (§4.4).
const ROLES: &[&str] = &[
    "davaci", "davacilar", "davali", "davalilar", "sanik", "saniklar", "musteki", "mustekiler", "katilan",
    "katilanlar", "magdur", "magdurlar", "tanik", "taniklar", "tanigi", "taniklari", "bilirkisi", "bilirkisiler",
    "tercuman", "supheli", "supheliler", "alacakli", "alacaklilar", "borclu", "borclular", "mudahil", "muris",
    "murisi", "vekili", "vekilleri", "asili", "asil", "mudafii", "mudafi", "velisi", "vasisi", "vasi", "kayyum",
    "kayyim", "sikayetci", "mirasci", "mirascilar", "mirascisi", "esi", "temsilcisi", "yetkilisi", "mumessili",
];

/// Company forms: the shape that types a party as `[SIRKET_n]`.
const COMPANY_GENERIC: &[&str] = &[
    "insaat", "ticaret", "tic", "sanayi", "san", "ltd", "sti", "limited", "anonim", "sirketi", "sirket", "as",
    "a", "s", "holding", "gida", "otomotiv", "tekstil", "turizm", "nakliyat", "nakliye", "lojistik", "enerji",
    "elektrik", "elektronik", "makine", "mimarlik", "muhendislik", "danismanlik", "yazilim", "bilisim", "pazarlama",
    "dis", "ic", "ve", "kooperatifi", "vakfi", "dernegi", "yapi", "tarim", "hayvancilik", "madencilik", "petrol",
    "akaryakit", "saglik", "egitim", "medya", "reklam", "matbaa", "mobilya", "emlak", "gayrimenkul", "yatirim",
    "uretim", "imalat", "metal", "plastik", "kimya", "ilac", "tibbi", "ticari", "isletmeleri", "hizmetleri",
    "grup", "group", "co", "sigorta", "sigortasi", "banka", "bankasi", "finans", "faktoring", "leasing",
    "kiralama", "kargo", "tasimacilik", "magazacilik", "market", "marketleri", "iletisim", "telekom", "ajans",
    "uluslararasi", "endustri", "endustrisi", "iplik", "orme", "boya", "cam", "seramik", "mermer", "beton",
    "gida", "su", "un", "yem", "et", "sut", "urunleri",
];

/// Common lowercase words that end a lowercase name guess.
const COMMON: &[&str] = &[
    "ve", "ile", "bu", "su", "o", "bir", "de", "da", "ki", "icin", "gibi", "olarak", "olan", "olup", "ise", "ne",
    "ya", "veya", "hem", "ama", "fakat", "ancak", "cunku", "sonra", "once", "kadar", "daha", "en", "cok", "az",
    "her", "hic", "bana", "beni", "benim", "ona", "onu", "onun", "bize", "biz", "siz", "sen", "ben", "geldi",
    "gelmedi", "geldiler", "dedi", "soyledi", "beyan", "etti", "etmedi", "oldu", "olmadi", "var", "yok", "hazir",
    "vekili", "asil", "tarafindan", "adina", "hakkinda", "aleyhine", "lehine", "ait", "aittir", "uzerine",
    "nedeniyle", "dolayi", "tarihinde", "gunu", "saat", "mahkemeye", "dosyaya", "dilekce", "ifade", "ifadesinde",
    "beyaninda", "sordu", "soruldu", "cevap", "verdi", "tanik", "davaci", "davali", "sanik", "ayni", "baska",
    "degildir", "degil", "kusurlu", "kusursuz", "olmadigini", "oldugunu", "ettigini", "istedi", "istemiyor",
    "biliyorum", "bilmiyorum", "gordum", "gormedim", "duydum", "tanirim", "tanimam", "bey", "hanim",
];

fn set(list: &'static [&'static str], cell: &'static OnceLock<HashSet<&'static str>>) -> &'static HashSet<&'static str> {
    cell.get_or_init(|| list.iter().copied().collect())
}

/// Court/procedure vocabulary (whole word or stem).
pub fn is_vocab(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    set(EXACT, &C).contains(key) || STEMS.iter().any(|s| key.starts_with(s))
}

pub fn is_role(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    set(ROLES, &C).contains(key)
}

pub fn is_company_generic(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    set(COMPANY_GENERIC, &C).contains(key)
}

pub fn is_common(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    set(COMMON, &C).contains(key)
}

/// One of the 81 provinces (and the two old names courts still print).
pub fn is_province(key: &str) -> bool {
    const P: &[&str] = &[
        "adana", "adiyaman", "afyonkarahisar", "afyon", "agri", "amasya", "ankara", "antalya", "artvin", "aydin",
        "balikesir", "bilecik", "bingol", "bitlis", "bolu", "burdur", "bursa", "canakkale", "cankiri", "corum",
        "denizli", "diyarbakir", "edirne", "elazig", "erzincan", "erzurum", "eskisehir", "gaziantep", "giresun",
        "gumushane", "hakkari", "hatay", "isparta", "mersin", "icel", "istanbul", "izmir", "kars", "kastamonu",
        "kayseri", "kirklareli", "kirsehir", "kocaeli", "konya", "kutahya", "malatya", "manisa", "kahramanmaras",
        "mardin", "mugla", "mus", "nevsehir", "nigde", "ordu", "rize", "sakarya", "samsun", "siirt", "sinop",
        "sivas", "tekirdag", "tokat", "trabzon", "tunceli", "sanliurfa", "usak", "van", "yozgat", "zonguldak",
        "aksaray", "bayburt", "karaman", "kirikkale", "batman", "sirnak", "bartin", "ardahan", "igdir", "yalova",
        "karabuk", "kilis", "osmaniye", "duzce",
    ];
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    set(P, &C).contains(key)
}

/// Turkish case and possessive endings a name may carry without an apostrophe ("yılmazın").
pub fn is_name_suffix(rest: &str) -> bool {
    const S: &[&str] = &[
        "a", "e", "i", "u", "o", "ya", "ye", "yi", "yu", "in", "un", "nin", "nun", "da", "de", "ta", "te", "dan",
        "den", "tan", "ten", "la", "le", "yla", "yle", "na", "ne", "ni", "nu", "nda", "nde", "ndan", "nden", "si",
        "su", "sin", "sun", "lar", "ler", "lari", "leri", "larin", "lerin", "ca", "ce", "dir", "dur", "tir", "tur",
        "gil", "giller", "lerle", "larla", "inin", "unun",
    ];
    S.contains(&rest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fold::key;

    #[test]
    fn lists_are_keys() {
        // Every entry must already be a matching key, or it can never match.
        for list in [EXACT, STEMS, ROLES, COMPANY_GENERIC, COMMON] {
            for w in list {
                assert_eq!(key(w), *w, "{w}");
            }
        }
        assert!(is_vocab(&key("MAHKEMEMİZCE")));
        assert!(is_vocab(&key("GEREĞİ")) && is_vocab(&key("DÜŞÜNÜLDÜ")));
        assert!(!is_vocab(&key("YILMAZ")));
        assert!(is_province(&key("IĞDIR")));
    }
}
