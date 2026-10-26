//! Every line a built-in bot says in its own voice, in Turkish and English, chosen by the bot's
//! language (docs/BOTS_HELPER_PLAN.md, "Failures are said, not swallowed").
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
}

/// Every line, for the tests.
#[cfg(test)]
pub(super) const ALL: [Line; 17] = [
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
