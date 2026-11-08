//! The words scenarios are made of: people's names, room topics and
//! message text in English, Arabic and both at once.
//!
//! Text here is plain, not escaped; [`crate::actors`] escapes it (3.4).

use crate::rng::Rng;

/// The language a room mostly talks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Ar,
    /// Both, often in one line: Arabic with English words, numbers and
    /// links, and the other way round.
    Mix,
}

/// Hosted identities in `busy`: their names and display names. An empty
/// display name means none, so apps show the uid.
pub const HOSTED: &[(&str, &str)] = &[
    ("aisha", "عائشة المنصوري"),
    ("omar", "Omar Farouk"),
    ("layla", "Layla | ليلى"),
    ("yusuf", "يوسف"),
    ("sara", "Sara Lindqvist"),
    ("khalid", "Khalid Al-Hammadi"),
    ("mariam", "مريم"),
    ("release-bot", "Release Bot"),
    ("hamad", "حمد بن راشد"),
    ("noura", "Noura N."),
    ("tariq", "Tariq"),
    ("fatima", "فاطمة الزهراء"),
    ("james", "James O'Connor"),
    ("mei", "Mei Chen"),
    ("zayd", "Zayd 🚲"),
    ("hessa", "حصة"),
    ("ali", "علي"),
    ("priya", "Priya Raman"),
    ("salem", "Salem"),
    ("reem", "Reem الريم"),
    ("idris", ""),
    ("lucas", "Lucas Moreau"),
    ("amna", "آمنة"),
    (
        "muhammad.s",
        "Muhammad Abdulrahman Al-Suwaidi bin Khalifa, Head of Community Partnerships (Dubai)",
    ),
    (
        "abdulrahman",
        "عبد الرحمن بن عبد العزيز آل محمد، منسق الفعاليات والشراكات",
    ),
    ("hind", "Hind (mod)"),
    ("nasser", "ناصر"),
    ("chloe", "Chloé Dubois"),
];

/// Guests in `busy`, without the `~`.
pub const GUESTS: &[(&str, &str)] = &[
    ("sam", "Sam"),
    ("visitor", "زائر"),
    ("anon42", ""),
    ("lina", "Lina"),
    ("ahmed", "أحمد"),
    ("kai", "Kai"),
    ("mo", "Mo ✨"),
    ("dana", "دانة"),
    ("tom", "Tom"),
    ("q", ""),
];

/// First names for the people of `huge`, with a display name each.
pub const FIRST_NAMES: &[(&str, &str)] = &[
    ("adam", "Adam"),
    ("amal", "أمل"),
    ("bilal", "Bilal"),
    ("dalia", "داليا"),
    ("elias", "Elias"),
    ("farah", "فرح"),
    ("ghada", "غادة"),
    ("hana", "Hana"),
    ("ibrahim", "إبراهيم"),
    ("jana", "Jana"),
    ("karim", "كريم"),
    ("lamia", "Lamia"),
    ("majid", "ماجد"),
    ("nadia", "Nadia"),
    ("osama", "أسامة"),
    ("rana", "Rana"),
    ("sami", "سامي"),
    ("talal", "Talal"),
    ("wafa", "وفاء"),
    ("yasmin", "Yasmin"),
    ("ziad", "زياد"),
    ("anna", "Anna"),
    ("ben", "Ben"),
    ("clara", "Clara"),
    ("david", "David"),
    ("eva", "Eva"),
    ("felix", "Felix"),
    ("grace", "Grace"),
    ("henry", "Henry"),
    ("iris", "Iris"),
];

/// Words that make the names and topics of `huge`'s rooms.
pub const ROOM_WORDS: &[&str] = &[
    "amber",
    "atlas",
    "basil",
    "cedar",
    "coral",
    "delta",
    "dune",
    "ember",
    "falcon",
    "fennel",
    "garnet",
    "harbor",
    "indigo",
    "jasmine",
    "juniper",
    "kestrel",
    "lagoon",
    "lantern",
    "maple",
    "meadow",
    "mint",
    "nomad",
    "oasis",
    "olive",
    "orbit",
    "palm",
    "pearl",
    "pepper",
    "quartz",
    "raven",
    "saffron",
    "sage",
    "sandstone",
    "sumac",
    "thyme",
    "tide",
    "umber",
    "violet",
    "wadi",
    "willow",
    "zaatar",
    "zenith",
];

/// What `huge`'s rooms are for.
pub const ROOM_KINDS: &[&str] = &[
    "team", "club", "crew", "lab", "guild", "circle", "desk", "notes", "chat", "ops", "build",
    "cafe", "house", "studio", "school",
];

const EN: &[&str] = &[
    "Morning all",
    "Did anyone see the build break last night?",
    "I'll take a look after lunch.",
    "Pushed a fix, can someone review?",
    "LGTM 👍",
    "That makes sense to me.",
    "Can we move the call to 3?",
    "Running ten minutes late, sorry",
    "Who's bringing the projector?",
    "Here's the doc: https://example.org/notes/q3-planning",
    "Not sure I agree, but happy to try it for a week.",
    "Thanks!",
    "haha",
    "ok",
    "Is the office open on Friday?",
    "The new release is out. Changelog in the usual place.",
    "Does anyone have a spare HDMI cable?",
    "I think the problem is the cache, not the network.",
    "Let's not ship on a Friday.",
    "Coffee?",
    "+1",
    "Great talk today, the slides are worth a second look.",
    "Reminder: retro is tomorrow at 10.",
    "I can't reproduce it on my machine.",
    "Have you tried turning it off and on again?",
    "Weather's perfect for a ride this evening.",
    "Booked the table for 8 people at 7:30.",
    "Can someone explain what this flag does?",
    "Merged. Thanks for the patience everyone.",
    "Deploying now, expect a minute of downtime.",
    "Where did we land on the naming question?",
    "Agreed. Let's write it down so we don't argue about it again.",
    "Back from leave! What did I miss?",
    "Photos from Saturday are in the shared album.",
    "I'll be offline until Monday.",
    "Typo in the README, fixed.",
    "Does 7pm work for everyone?",
    "This is the best thread I've read all week.",
    "Quick question: is the API rate limited?",
    "Done ✅",
    "🎉🎉🎉",
    "The train is delayed again 🙃",
    "Who wants to pair on this tomorrow?",
    "Can we get a test for that?",
    "Lunch is on me today.",
    "Wait, really?",
    "Good night everyone",
    "Same here.",
];

const AR: &[&str] = &[
    "صباح الخير جميعاً",
    "السلام عليكم ورحمة الله",
    "وعليكم السلام",
    "متى الاجتماع القادم؟",
    "شكراً جزيلاً",
    "إن شاء الله نلتقي يوم الخميس",
    "تمام، اتفقنا",
    "من سيحضر القهوة؟",
    "الجو اليوم جميل جداً",
    "أرسلت لكم الملف على البريد",
    "هل وصل الجميع؟",
    "عندي سؤال بسيط",
    "ما شاء الله، عمل رائع",
    "أنا في الطريق",
    "سأتأخر قليلاً، آسف",
    "الله يعطيك العافية",
    "هل تعرف أحداً يصلح السيارات؟",
    "الإفطار عندنا هذا الأسبوع",
    "رمضان كريم",
    "عيد مبارك وكل عام وأنتم بخير",
    "نسيت المفتاح في المكتب 😅",
    "خلونا نبدأ بعد صلاة المغرب",
    "الصور الجميلة من رحلة الأمس",
    "كم الساعة عندكم الآن؟",
    "أحسنت",
    "نعم",
    "لا أعتقد ذلك",
    "ممكن نؤجلها للأسبوع القادم؟",
    "جزاك الله خيراً",
    "تصبحون على خير",
    "أين نلتقي؟ عند المقهى المعتاد؟",
    "الحمد لله على السلامة",
    "قرأت المقال، فكرة ممتازة",
    "نحتاج متطوعين للتنظيم",
    "مبروك! 🎉",
    "الطريق مزدحم جداً اليوم",
    "تم ✅",
    "هل جربتم المطعم الجديد؟",
    "الكتاب القادم من اختيار مريم",
    "أنا موافق",
];

const MIX: &[&str] = &[
    "الاجتماع الساعة 3pm في الـ office",
    "هل جربت iOS 26 على الجهاز القديم؟",
    "Meeting moved to الخميس, same time",
    "الرابط هنا: https://example.org/مستند",
    "Deploy done، شكراً للجميع",
    "رقم الغرفة 204 في الطابق ٣",
    "I said يلا, let's go!",
    "PR #4821 جاهز للمراجعة",
    "عندي bug غريب في الـ cache",
    "See you at المجلس tonight",
    "الحجز باسم Sara، الساعة ٨ مساءً",
    "Version 2.3.1 فيها إصلاح للمشكلة",
    "ميزانية Q3 هي 45,000 AED تقريباً",
    "The word is مرحبا, not مرحبًا, in the mockup",
    "خلصت الـ review, LGTM",
    "شو رأيكم في the new logo؟",
    "Flight EK 202 يصل ٦:٤٠ صباحاً",
    "inshallah tomorrow, إن شاء الله",
    "قرأت الـ thread كله، مقنع",
    "WiFi password: قهوة2026",
    "يوم الـ hackathon هو السبت ١٤ نوفمبر",
    "ok تمام 👍",
    "Ali said «ما في مشكلة», so we're good",
    "صورة الـ screenshot مرفقة في الـ ticket",
    "Matches at 7 — الملعب الجديد near the metro",
];

const LONG_EN: &[&str] = &[
    "I've been thinking about this for a while, and I want to write it down properly before \
     the meeting, because every time we discuss it in person we end up going in circles.",
    "The short version is that the current setup works for the five of us, but it will not \
     work for fifty, and we keep making decisions as if we will always be five.",
    "Concretely: the onboarding doc is out of date, nobody owns the release checklist, and \
     half of the alerts page is noise that we have all learned to ignore, which is the worst \
     possible outcome for an alerts page.",
    "None of this is anyone's fault. It's what happens when a group grows faster than its \
     habits. But it does mean we should spend the next two weeks on boring things.",
    "I'd propose that each of us picks one of these, writes a one-page plan, and we review \
     them together next Thursday. If that sounds like too much process, tell me now.",
    "Also, for the record, I think the new office is great and the coffee machine is the \
     best thing that has happened to this team all year.",
];

const LONG_AR: &[&str] = &[
    "أردت أن أكتب هذا بهدوء قبل اجتماع الغد، لأننا كلما تحدثنا فيه وجهاً لوجه انتهينا إلى \
     النقطة نفسها دون قرار واضح.",
    "باختصار، الطريقة الحالية تناسبنا ونحن خمسة أشخاص، لكنها لن تناسبنا ونحن خمسون، ونحن ما \
     زلنا نتخذ قراراتنا وكأن عددنا لن يتغير أبداً.",
    "دليل الانضمام قديم، ولا أحد مسؤول عن قائمة الإصدار، ونصف التنبيهات ضجيج تعودنا على \
     تجاهله، وهذا أسوأ ما يمكن أن يحدث لصفحة التنبيهات.",
    "لا ألوم أحداً على ذلك، فهذا ما يحدث عندما تكبر المجموعة أسرع من عاداتها. لكنه يعني أن \
     علينا أن نقضي الأسبوعين القادمين في أعمال مملة ولكنها ضرورية.",
    "أقترح أن يختار كل واحد منا موضوعاً، ويكتب خطة من صفحة واحدة، ثم نراجعها معاً يوم \
     الخميس القادم. وإن بدا لكم هذا كثيراً فأخبروني الآن.",
    "وللتسجيل فقط: المكتب الجديد رائع، وآلة القهوة أفضل ما حدث لهذا الفريق هذا العام.",
];

/// Reactions, usually a single emoji (5.3).
pub const REACTIONS: &[&str] = &[
    "👍", "❤️", "😂", "🎉", "🙏", "👀", "🔥", "✅", "😮", "🤲", "💯", "+1",
];

/// Topics, by language.
const TOPICS_EN: &[&str] = &[
    "Everything else",
    "Bugs, crashes and other surprises",
    "Release planning and the train schedule",
    "Show your work, get honest feedback",
    "Weekly meetups, Thursdays 7pm",
    "No question too small",
];
const TOPICS_AR: &[&str] = &[
    "للنقاش العام بين الجيران",
    "القهوة والحديث",
    "تنظيم الإفطار الجماعي",
    "أخبار العائلة",
    "حلقة التلاوة الأسبوعية",
];
const TOPICS_MIX: &[&str] = &[
    "Arabic type, kashida و كل ما يتعلق بالخط",
    "مباريات كل خميس — 7pm",
    "Translations: English ⇄ العربية",
    "Dubai meetups و الفعاليات",
];

/// A topic for a room in `lang`.
pub fn topic(rng: &mut Rng, lang: Lang) -> String {
    (*rng.pick(match lang {
        Lang::En => TOPICS_EN,
        Lang::Ar => TOPICS_AR,
        Lang::Mix => TOPICS_MIX,
    }))
    .to_owned()
}

/// A topic long enough to need truncating anywhere it is shown, within
/// the 512 bytes a topic may have (6.2).
pub fn long_topic() -> String {
    "A room for testing what happens when a topic goes on and on: it should truncate \
     cleanly, wrap where it is allowed to, and never push the room's name or the time off \
     the row. هذا النص العربي هنا ليتأكد أن الاتجاه يبقى صحيحاً في منتصف السطر، ثم نعود \
     إلى English again, with a link https://example.org/a/very/long/path at the end."
        .to_owned()
}

/// One line of chat in `lang`.
pub fn line(rng: &mut Rng, lang: Lang) -> String {
    let set = match lang {
        Lang::En => EN,
        Lang::Ar => AR,
        // Mixed rooms mix everything, mostly lines with both.
        Lang::Mix => match rng.below(4) {
            0 => EN,
            1 => AR,
            _ => MIX,
        },
    };
    (*rng.pick(set)).to_owned()
}

/// A long message, of several paragraphs, in `lang`: for a mixed room,
/// paragraphs in both. `paragraphs` may be more than there are; they then
/// repeat, which makes messages of several thousand bytes.
pub fn long_message(rng: &mut Rng, lang: Lang, paragraphs: usize) -> String {
    let mut out = Vec::new();
    for i in 0..paragraphs {
        let set = match lang {
            Lang::En => LONG_EN,
            Lang::Ar => LONG_AR,
            Lang::Mix => {
                if rng.chance(0.5) {
                    LONG_EN
                } else {
                    LONG_AR
                }
            }
        };
        out.push(set[i % set.len()]);
    }
    out.join("\n\n")
}

/// The new text of an edited message: the old one, corrected.
pub fn edited(rng: &mut Rng, lang: Lang, old: &str) -> String {
    let fix = match lang {
        Lang::Ar => *rng.pick(&[" (تصحيح)", "، أقصد الخميس", " 🙏"]),
        _ => *rng.pick(&[" (fixed)", ", I mean Thursday", " — sorry, typo", "!"]),
    };
    let mut text = old.trim_end().to_owned();
    // Keep an edit of a long message within a line's limits.
    if text.len() > 3000 {
        let mut cut = 3000;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text.push_str(fix);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_fit_the_protocol() {
        for (name, display) in HOSTED.iter().chain(GUESTS).chain(FIRST_NAMES) {
            assert!(name.parse::<risala_proto::names::Name>().is_ok(), "{name}");
            // 8.2: a display name is at most 128 bytes.
            assert!(display.len() <= 128, "{display}: {} bytes", display.len());
        }
        assert!(long_topic().len() <= 512);
        for r in REACTIONS {
            assert!(r.len() <= risala_proto::types::MAX_REACTION);
        }
    }
}
