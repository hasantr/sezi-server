//! Every line a built-in bot says in its own voice, in Turkish and English, chosen by the bot's
//! language (docs/BOTS_HELPER_PLAN.md, "Failures are said, not swallowed") — and the one line the
//! relay says for a PROGRAM bot, when its queue refuses a member (`backlog.rs`).
//!
//! The relay composes these because here the relay IS the speaker: a built-in bot's fixed lines
//! reach a member as the bot's message, with no app in between to translate a code. The model's
//! own answers are not here — they are in whatever language the owner's instructions ask for.

use crate::bots::builtin_rules::Lang;

/// One fixed line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Line {
    /// The model call failed for a reason the owner has to fix (key, model, refusal).
    AiUnavailable,
    /// The model call kept failing for a passing reason (unreachable, overloaded).
    TryLater,
    /// Past the 50 model calls a member gets a day.
    DailyLimit,
    /// Asked before an AI bot writes a row; the row follows it.
    ConfirmRow,
    /// After the row it follows.
    ConfirmHint,
    /// The row the member confirmed is in the sheet.
    RowSaved,
    /// The member said no.
    RowDiscarded,
    /// A yes or no to a proposal older than 10 minutes.
    ProposalLapsed,
    /// The first failed attempt to write a row.
    SheetRetrying,
    /// A row queued behind one the sheet keeps refusing.
    SheetQueued,
    /// A row landed after failed attempts.
    SheetLandedLate,
    /// A row that could not be written for a day.
    SheetGaveUp,
    /// What the owner's "Dene" sends.
    TestMessage,
    /// A sheet bot whose sheet is not connected yet.
    NotSetUp,
    /// Heads a row proposed for a call in a group, sent 1:1: which group (`{room}`).
    ProposalFromRoom,
    /// Heads a proposal that replaced one still waiting for an answer.
    ProposalReplaced,
    /// Past the rows a member may send a sheet bot a day (`builtin_store::DAILY_ROWS`).
    SheetDailyLimit,
    /// A PROGRAM bot's queue holds too many of this member's messages, or everybody's
    /// (`backlog.rs`): the relay speaks for the bot, whose program never saw the message.
    ProgramBusy,
    /// A file sent to a built-in bot that reads text only (sheet, AI): said once per message, so
    /// the member is never left with "delivered" and silence (H3).
    TextOnly,
    // ── The hearing-minutes bot (docs/HEARINGS_BOT_PLAN.md) ──
    /// The member is not an active member of the bot's `allowed_room` (decision 2).
    HearingsNotAllowed,
    /// `hearings/no-text-layer`: a scan, or a text layer without ToUnicode.
    HearingsNoTextLayer,
    /// `hearings/not-a-record` (the rules' or the model's verdict).
    HearingsNotARecord,
    /// `hearings/too-large`, `too-many-pages`, `pdf-content-limit`, `too-much-text`.
    HearingsTooLarge,
    /// `hearings/pdf-encrypted`.
    HearingsPdfEncrypted,
    /// `hearings/pdf-unreadable`.
    HearingsPdfUnreadable,
    /// `hearings/unsupported-type`: neither a PDF nor text.
    HearingsUnsupportedType,
    /// The file did not open (gone, not the sender's, forged manifest, the store down).
    HearingsFileUnavailable,
    /// `hearings/needs-paid-plan`: processing the file kept ending the invocation (CPU limit).
    HearingsTooHeavy,
    /// Heads a rule-only answer when the summary could not be made (masking refused, the model
    /// failed or answered something that did not pass the checks, no key).
    HearingsSummaryFailed,
    /// Heads a criminal case's answer: no model (decision 3).
    HearingsCriminal,
    /// Heads a rule-only answer past the member's model calls for the day.
    HearingsDailyLimit,
    /// Heads a rule-only answer past the BOT's model calls for the day (the owner's
    /// `daily_calls`, every member together).
    HearingsBotDailyLimit,
    /// Ends an answer with a row to write: `{esas}` is the record's esas no.
    HearingsAskSheet,
    /// The rules found no court or no esas no: there is no row to find or add.
    HearingsNoRowKey,
    /// The confirmed row updated an existing one: `{row}` is its number.
    HearingsRowUpdated,
    /// The confirmed row was added: `{row}` is its number.
    HearingsRowAppended,
    /// A call in a room (H7 is not built): the record is to be sent 1:1.
    HearingsOneToOneOnly,
}

/// Every line, for the tests.
#[cfg(test)]
pub(super) const ALL: [Line; 37] = [
    Line::AiUnavailable,
    Line::TryLater,
    Line::DailyLimit,
    Line::ConfirmRow,
    Line::ConfirmHint,
    Line::RowSaved,
    Line::RowDiscarded,
    Line::ProposalLapsed,
    Line::SheetRetrying,
    Line::SheetQueued,
    Line::SheetLandedLate,
    Line::SheetGaveUp,
    Line::TestMessage,
    Line::NotSetUp,
    Line::ProposalFromRoom,
    Line::ProposalReplaced,
    Line::SheetDailyLimit,
    Line::ProgramBusy,
    Line::TextOnly,
    Line::HearingsNotAllowed,
    Line::HearingsNoTextLayer,
    Line::HearingsNotARecord,
    Line::HearingsTooLarge,
    Line::HearingsPdfEncrypted,
    Line::HearingsPdfUnreadable,
    Line::HearingsUnsupportedType,
    Line::HearingsFileUnavailable,
    Line::HearingsTooHeavy,
    Line::HearingsSummaryFailed,
    Line::HearingsCriminal,
    Line::HearingsDailyLimit,
    Line::HearingsBotDailyLimit,
    Line::HearingsAskSheet,
    Line::HearingsNoRowKey,
    Line::HearingsRowUpdated,
    Line::HearingsRowAppended,
    Line::HearingsOneToOneOnly,
];

pub(super) fn line(lang: Lang, l: Line) -> &'static str {
    match (lang, l) {
        (Lang::Tr, Line::AiUnavailable) => "Şu an yanıt veremiyorum. Bot sahibine haber verildi.",
        (Lang::En, Line::AiUnavailable) => "I can't answer right now. The bot's owner has been told.",
        (Lang::Tr, Line::TryLater) => "Mesajını şu an işleyemedim. Lütfen biraz sonra tekrar yaz.",
        (Lang::En, Line::TryLater) => "I couldn't handle your message right now. Please write again a little later.",
        (Lang::Tr, Line::DailyLimit) => "Bugünlük sınıra ulaştın (günde 50 mesaj). Yarın yine yazabilirsin.",
        (Lang::En, Line::DailyLimit) => "You've reached today's limit (50 messages a day). You can write again tomorrow.",
        (Lang::Tr, Line::ConfirmRow) => "Şunu kaydedeyim mi?",
        (Lang::En, Line::ConfirmRow) => "Shall I save this?",
        (Lang::Tr, Line::ConfirmHint) => "evet / hayır",
        (Lang::En, Line::ConfirmHint) => "yes / no",
        (Lang::Tr, Line::RowSaved) => "Kaydedildi.",
        (Lang::En, Line::RowSaved) => "Saved.",
        (Lang::Tr, Line::RowDiscarded) => "Tamam, kaydetmedim.",
        (Lang::En, Line::RowDiscarded) => "OK, I didn't save it.",
        (Lang::Tr, Line::ProposalLapsed) => {
            "Bu öneri 10 dakika içinde onaylanmadığı için düştü; hiçbir şey kaydedilmedi."
        }
        (Lang::En, Line::ProposalLapsed) => "That proposal lapsed after 10 minutes; nothing was saved.",
        (Lang::Tr, Line::SheetRetrying) => "Tabloya yazamadım; yeniden deneyeceğim.",
        (Lang::En, Line::SheetRetrying) => "I couldn't write to the sheet; I'll keep trying.",
        (Lang::Tr, Line::SheetQueued) => "Tabloya şu an ulaşılamıyor; kaydın, ulaşılınca yazılacak.",
        (Lang::En, Line::SheetQueued) => "The sheet can't be reached right now; your entry will be written when it is.",
        (Lang::Tr, Line::SheetLandedLate) => "Tabloya yazıldı (gecikmeli).",
        (Lang::En, Line::SheetLandedLate) => "Written to the sheet (late).",
        (Lang::Tr, Line::SheetGaveUp) => {
            "Bir gün boyunca tabloya yazamadım ve vazgeçtim; bu kayıt yazılmadı."
        }
        (Lang::En, Line::SheetGaveUp) => "I couldn't write to the sheet for a day and gave up; this entry was not saved.",
        (Lang::Tr, Line::TestMessage) => "Merhaba! Bu, bot sahibinin bir denemesi.",
        (Lang::En, Line::TestMessage) => "Hello! This is a test from the bot's owner.",
        (Lang::Tr, Line::NotSetUp) => "Bu bot henüz kurulmadı; mesajın kaydedilmedi.",
        (Lang::En, Line::NotSetUp) => "This bot isn't set up yet; your message was not saved.",
        (Lang::Tr, Line::ProposalFromRoom) => "“{room}” grubundaki mesajın için:",
        (Lang::En, Line::ProposalFromRoom) => "For your message in the group \"{room}\":",
        (Lang::Tr, Line::ProposalReplaced) => "Önceki öneri geçersiz; cevabın bunun için.",
        (Lang::En, Line::ProposalReplaced) => "This replaces the earlier proposal; your answer is for this one.",
        (Lang::Tr, Line::SheetDailyLimit) => {
            "Bugünlük kayıt sınırına ulaştın (günde 200 kayıt). Bugün bundan sonra yazdıkların kaydedilmeyecek; yarın yine yazabilirsin."
        }
        (Lang::En, Line::SheetDailyLimit) => {
            "You've reached today's limit (200 entries a day). Nothing more you write today will be saved; you can write again tomorrow."
        }
        (Lang::Tr, Line::ProgramBusy) => {
            "Bu bot şu an yetişemiyor: bekleyen çok fazla mesajı var, bu yüzden şimdi yazdıkların programına iletilmiyor. Biraz sonra tekrar yaz."
        }
        (Lang::En, Line::ProgramBusy) => {
            "This bot can't keep up right now: too many messages are waiting for it, so what you write now is not passed on to its program. Please write again a little later."
        }
        (Lang::Tr, Line::TextOnly) => {
            "Dosyaları açamıyorum; yalnızca yazılı mesajları okuyorum. Söylemek istediğini yazıyla gönderebilirsin."
        }
        (Lang::En, Line::TextOnly) => "I can't open files; I read written messages only. You can send what you want to say as text.",
        (Lang::Tr, Line::HearingsNotAllowed) => "Bu botu kullanma yetkin yok.",
        (Lang::En, Line::HearingsNotAllowed) => "You're not allowed to use this bot.",
        (Lang::Tr, Line::HearingsNoTextLayer) => {
            "Bu belgede okunabilir metin yok (taranmış olabilir). UYAP'tan indirilen PDF'i gönderin."
        }
        (Lang::En, Line::HearingsNoTextLayer) => {
            "This document has no readable text (it may be a scan). Please send the PDF downloaded from UYAP."
        }
        (Lang::Tr, Line::HearingsNotARecord) => {
            "Bu bir duruşma tutanağına benzemiyor. Tutanağın UYAP'tan indirilen PDF'ini ya da metnini gönder."
        }
        (Lang::En, Line::HearingsNotARecord) => {
            "This doesn't look like a hearing record. Send the record's PDF from UYAP, or its text."
        }
        (Lang::Tr, Line::HearingsTooLarge) => "Bu belge çok büyük; en çok 10 MB ve 40 sayfa okuyabiliyorum.",
        (Lang::En, Line::HearingsTooLarge) => "This document is too large; I read at most 10 MB and 40 pages.",
        (Lang::Tr, Line::HearingsPdfEncrypted) => "Bu PDF parolayla korunuyor, açamıyorum. Parolasız halini gönder.",
        (Lang::En, Line::HearingsPdfEncrypted) => "This PDF is password-protected and I can't open it. Send it without the password.",
        (Lang::Tr, Line::HearingsPdfUnreadable) => "Bu PDF açılamadı (bozuk olabilir). UYAP'tan yeniden indirip gönder.",
        (Lang::En, Line::HearingsPdfUnreadable) => "This PDF couldn't be opened (it may be damaged). Download it from UYAP again and send it.",
        (Lang::Tr, Line::HearingsUnsupportedType) => "Yalnızca PDF ya da düz metin okuyabiliyorum.",
        (Lang::En, Line::HearingsUnsupportedType) => "I can read only a PDF or plain text.",
        (Lang::Tr, Line::HearingsFileUnavailable) => "Dosyanı açamadım; lütfen yeniden gönder.",
        (Lang::En, Line::HearingsFileUnavailable) => "I couldn't open your file; please send it again.",
        (Lang::Tr, Line::HearingsTooHeavy) => {
            "Bu belge bu sunucuda işlenemedi (sunucunun işlem sınırı aşıldı). Bot sahibine haber verildi."
        }
        (Lang::En, Line::HearingsTooHeavy) => {
            "This document couldn't be processed on this server (its processing limit was reached). The bot's owner has been told."
        }
        (Lang::Tr, Line::HearingsSummaryFailed) => "Özet şu an yapılamadı; kurallarla okunanlar:",
        (Lang::En, Line::HearingsSummaryFailed) => "The summary couldn't be made right now; what the rules read:",
        (Lang::Tr, Line::HearingsCriminal) => "Ceza dosyası: yapay zekâya gönderilmedi, yalnızca kurallarla okundu.",
        (Lang::En, Line::HearingsCriminal) => "A criminal case: it was not sent to the AI, only read by the rules.",
        (Lang::Tr, Line::HearingsDailyLimit) => "Bugünkü özet sınırına ulaştın (günde 50); kurallarla okunanlar:",
        (Lang::En, Line::HearingsDailyLimit) => "You've reached today's limit of summaries (50 a day); what the rules read:",
        (Lang::Tr, Line::HearingsBotDailyLimit) => {
            "Bu botun bugünkü yapay zekâ özeti sınırı doldu; yarın yeniden açılır. Kurallarla okunanlar:"
        }
        (Lang::En, Line::HearingsBotDailyLimit) => {
            "This bot's AI summaries for today have run out; they are back tomorrow. What the rules read:"
        }
        (Lang::Tr, Line::HearingsAskSheet) => {
            "Tabloya yazayım mı? ({esas} satırı varsa güncellenir, yoksa eklenir) evet / hayır"
        }
        (Lang::En, Line::HearingsAskSheet) => {
            "Shall I write it to the sheet? (the {esas} row is updated if it exists, added if not) yes / no"
        }
        (Lang::Tr, Line::HearingsNoRowKey) => "Mahkeme ya da esas no okunamadığı için tabloya yazamıyorum.",
        (Lang::En, Line::HearingsNoRowKey) => "I can't write this to the sheet: the court or the case number couldn't be read.",
        (Lang::Tr, Line::HearingsRowUpdated) => "Kaydedildi: tablonun {row}. satırı güncellendi.",
        (Lang::En, Line::HearingsRowUpdated) => "Saved: row {row} of the sheet was updated.",
        (Lang::Tr, Line::HearingsRowAppended) => "Kaydedildi: tabloya yeni satır eklendi ({row}. satır).",
        (Lang::En, Line::HearingsRowAppended) => "Saved: a new row was added to the sheet (row {row}).",
        (Lang::Tr, Line::HearingsOneToOneOnly) => "Duruşma tutanağını bana birebir sohbette gönder.",
        (Lang::En, Line::HearingsOneToOneOnly) => "Please send me the hearing record in our one-to-one chat.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_is_said_in_both_languages_and_differs_between_them() {
        for l in ALL {
            let (tr, en) = (line(Lang::Tr, l), line(Lang::En, l));
            assert!(!tr.trim().is_empty() && !en.trim().is_empty(), "{l:?}");
            assert_ne!(tr, en, "{l:?} is not translated");
            assert!(en.is_ascii(), "{l:?}: the English line carries Turkish letters");
        }
    }
}
