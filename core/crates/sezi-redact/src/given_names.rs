//! The given-name gazetteer of the residual net (§4.5), as matching keys.
//!
//! The plan asks for 2–3 thousand entries from published name-frequency lists. None was available
//! offline when this was written, so this is the ~600 most frequent Turkish given names written
//! from general knowledge: enough to catch the common case, and the obvious place to grow. Every
//! entry only ever over-masks a Capitalized pair.

use std::collections::HashSet;
use std::sync::OnceLock;

const NAMES: &[&str] = &[
    // male
    "ahmet", "mehmet", "mustafa", "ali", "huseyin", "hasan", "ibrahim", "ismail", "osman", "yusuf", "murat",
    "omer", "ramazan", "halil", "suleyman", "abdullah", "mahmut", "recep", "salih", "fatih", "kadir", "emre",
    "hakan", "kemal", "yasar", "orhan", "adem", "metin", "mevlut", "serkan", "yakup", "hamza", "burak", "cengiz",
    "cem", "coskun", "erkan", "ercan", "erdal", "erol", "ersin", "ertan", "ertugrul", "fikret", "gokhan", "hayri",
    "hikmet", "ilhan", "ilker", "kenan", "levent", "mert", "muharrem", "nevzat", "oguz", "onur", "ozan", "ozkan",
    "ozgur", "ridvan", "sadik", "sait", "selim", "semih", "serdar", "sinan", "tamer", "tarik", "tayfun", "tuncay",
    "turgay", "ugur", "umut", "volkan", "yasin", "yavuz", "yildirim", "zafer", "zeki", "baris", "bayram", "bekir",
    "bilal", "bulent", "can", "cemal", "cevdet", "dogan", "enes", "enver", "eren", "erhan", "ferhat", "furkan",
    "gurkan", "harun", "haydar", "idris", "irfan", "kaan", "kerem", "kursat", "mesut", "musa", "nail", "necati",
    "nihat", "numan", "nuri", "oktay", "oner", "ozcan", "rahmi", "recai", "refik", "riza", "sabri", "sami",
    "sedat", "seref", "sukru", "sener", "tahir", "taner", "tolga", "ufuk", "vedat", "veli", "vural", "yunus",
    "zekeriya", "berk", "efe", "emir", "eymen", "alp", "alper", "arda", "batuhan", "berkay", "deniz", "dogukan",
    "ege", "emin", "ensar", "erdem", "gokay", "hilmi", "ihsan", "kamil", "lutfi", "mecit", "mithat", "muammer",
    "nazim", "necdet", "nedim", "nurettin", "ozer", "rasim", "resat", "sahin", "saban", "sefa", "selcuk", "sevket",
    "talat", "tevfik", "turan", "umit", "utku", "vahit", "yahya", "yalcin", "yener", "yigit", "zihni", "aydin",
    "aytac", "battal", "birol", "cafer", "celal", "cihan", "davut", "ekrem", "emrah", "engin", "erdinc", "ergun",
    "fahri", "faruk", "fehmi", "ferit", "fuat", "galip", "guven", "hulusi", "ilyas", "ismet", "kazim", "kudret",
    "mahir", "nusret", "okan", "oral", "orhun", "rifat", "rustu", "sabahattin", "sadettin", "selahattin",
    "sinasi", "suat", "tacettin", "taylan", "timur", "tufan", "turgut", "vehbi", "zeynel", "abdulkadir",
    "abdurrahman", "aziz", "bahattin", "cuneyt", "dursun", "eyup", "fevzi", "haci", "hamdi", "hulki", "muzaffer",
    "nizamettin", "sebahattin", "seyfettin", "sezai", "zubeyir", "abdulkerim", "abdulsamet", "agah", "akif",
    "alaattin", "alparslan", "altan", "anil", "atakan", "atilla", "ayhan", "aykut", "bahadir", "bedirhan", "behcet",
    "bora", "bugra", "canberk", "caner", "celil", "cemil", "cetin", "cuma", "demir", "demirhan", "durmus", "ebubekir",
    "egemen", "ekin", "elvan", "emrullah", "ender", "eray", "erdogan", "ergin", "erkin", "eser", "fadil", "ferdi",
    "feridun", "fethi", "gazi", "gencay", "giray", "gokcan", "gokmen", "gungor", "habib", "hakki", "hami", "hidayet",
    "huseyin", "ilkay", "iskender", "kahraman", "kayhan", "koray", "korkmaz", "kubilay", "kutay", "medeni",
    "melih", "memduh", "mazhar", "mucahit", "muhammed", "muhammet", "muhittin", "murtaza", "mutlu", "nadir",
    "naim", "namik", "nazmi", "nebi", "nejat", "nezih", "niyazi", "nuh", "ogun", "ogulcan", "omur", "ozdemir",
    "ozgun", "polat", "remzi", "resit", "sakir", "sami", "savas", "sedat", "selami", "selman", "senol", "serhat",
    "serhan", "sezgin", "sitki", "soner", "tahsin", "tarkan", "tekin", "temel", "tuna", "tuncer",
    "tunahan", "ulas", "umran", "unal", "uygar", "vahap", "vedat", "yagiz", "yasin", "yekta", "yucel", "yuksel",
    "yusuf", "zahit", "zakir", "ziya",
    // female
    "ayse", "fatma", "emine", "hatice", "zeynep", "elif", "meryem", "sultan", "hanife", "zehra", "havva", "hacer",
    "esra", "merve", "ozlem", "ozge", "ozden", "songul", "sevgi", "sevim", "sibel", "derya", "dilek", "ebru", "ece",
    "eda", "ela", "emel", "esin", "esma", "feride", "filiz", "fulya", "gamze", "gizem", "gonul", "gul", "gulay",
    "gulsen", "gulten", "gulizar", "guler", "gulsum", "hale", "handan", "hande", "hilal", "hulya", "ilknur", "ipek",
    "irem", "kader", "kubra", "leyla", "melek", "melike", "melis", "meltem", "nazan", "nazli", "nermin", "nesrin",
    "nihal", "nilay", "nur", "nuray", "nurten", "oya", "pinar", "rabia", "saadet", "seda", "sedef", "selin",
    "selma", "semra", "serap", "serpil", "sevda", "sevil", "sevinc", "sinem", "suna", "tugba", "tulay", "tuba",
    "tulin", "yasemin", "yeliz", "yildiz", "yesim", "zuhal", "zubeyde", "ayten", "aynur", "aysun", "aylin",
    "aysegul", "asli", "aslihan", "arzu", "asiye", "ayfer", "aygul", "bahar", "banu", "basak", "belgin", "berna",
    "betul", "beyza", "burcu", "buse", "canan", "cansu", "ceren", "cigdem", "damla", "demet", "didem", "dilara",
    "duygu", "ecem", "elcin", "esengul", "eylul", "fadime", "fatos", "ferda", "figen", "gulbahar", "guldane",
    "gulnur", "gulperi", "guzin", "habibe", "halime", "hamide", "hayriye", "hazal", "huriye", "inci", "isil",
    "kevser", "kezban", "lale", "latife", "makbule", "mehtap", "menekse", "mine", "mukaddes", "munevver",
    "nagihan", "naciye", "necla", "nefise", "neslihan", "nevin", "nilgun", "nilufer", "nursel", "nurcan", "nurhan",
    "perihan", "rukiye", "sabriye", "safiye", "sakine", "saliha", "sema", "semiha", "sengul", "serife", "sevilay",
    "sukran", "sule", "sukriye", "yeter", "yurdagul", "zahide", "zarife", "zekiye", "zeliha", "zerrin", "zuleyha",
    "zumrut", "adalet", "aliye", "ayla", "bedriye", "cemile", "cennet", "durdane", "dondu", "esme", "fikriye",
    "gulcan", "gulistan", "hasibe", "hatun", "hediye", "kadriye", "meral", "muazzez", "nazife", "nebahat",
    "nezihe", "nuriye", "raziye", "remziye", "refika", "saime", "sadiye", "selver", "sennur", "sermin", "sevgul",
    "solmaz", "turkan", "yadigar", "zuhre", "aleyna", "asya", "azra", "begum", "belma", "beril", "berrin",
    "birgul", "birsen", "buket", "busra", "cagla", "cemre", "defne", "deniz", "dilan", "dilay", "dilber",
    "dilsad", "ecrin", "ekin", "elanur", "elvan", "emine", "esengul", "ezgi", "fatmanur", "feyza", "gokce",
    "gulden", "gulfem", "gulhan", "gulsah", "gunes", "hacer", "hafize", "hamiyet", "hanim", "hulya", "ikbal",
    "ilkim", "kardelen", "kubra", "lamia", "mediha", "melda", "mihriban", "miray", "muge", "mujgan", "nalan",
    "nazmiye", "nehir", "nesibe", "neval", "nida", "nilsu", "nisa", "nurgul", "nurhayat", "ozgul", "pembe",
    "rana", "reyhan", "rumeysa", "sabahat", "sabiha", "sacide", "seher", "selda", "senay", "sennur", "sevde",
    "seyma", "sevtap", "simge", "sila", "sukriye", "sumeyye", "tuana", "tugce", "ulku", "umay", "vildan",
    "yagmur", "yaren", "yonca", "zeren", "zekiye",
];

/// Given names that are also everyday lowercase words: never guessed from lowercase text alone.
const AMBIGUOUS: &[&str] = &[
    "can", "deniz", "umut", "umit", "baris", "bahar", "kader", "nur", "gul", "derya", "yildiz", "ozgur", "sevgi",
    "sevda", "sevinc", "inci", "ece", "onur", "adalet", "cennet", "ipek", "lale", "menekse", "damla", "pinar",
    "hilal", "melek", "sultan", "guven", "kudret", "zafer", "yasar", "aydin", "sahin", "dogan", "cihan", "gazi",
    "haci", "nail", "mert", "ela", "eda", "yeter", "dilek", "sema", "mine", "elif", "ozan", "efe", "ege", "alp",
    "kaan", "emin", "aziz", "kamil", "salih", "sadik", "hamdi", "selim", "sami", "veli", "yunus", "turan", "timur",
    "ali", "fatih", "kemal", "hikmet", "kerem", "ihsan", "irfan", "kadir", "bayram", "ramazan", "recep", "cuma",
    "mutlu", "umran", "demir", "temel", "savas", "tuna", "gunes", "nehir", "ekin", "hanim", "pembe", "seher",
    "sila", "yagmur", "yonca", "asil", "basak", "begum", "nadir", "naim", "medeni", "polat", "tekin", "ulku",
    "korkmaz", "kahraman", "huriye", "omur", "asli", "nesrin", "irmak", "sevim", "esen", "cansu", "ozge",
];

pub fn is_given(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    C.get_or_init(|| NAMES.iter().copied().collect()).contains(key)
}

pub fn is_ambiguous(key: &str) -> bool {
    static C: OnceLock<HashSet<&str>> = OnceLock::new();
    C.get_or_init(|| AMBIGUOUS.iter().copied().collect()).contains(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_keys() {
        for w in NAMES.iter().chain(AMBIGUOUS) {
            assert_eq!(crate::fold::key(w), *w, "{w}");
        }
        assert!(is_given("ayse") && is_given("mehmet"));
    }
}
