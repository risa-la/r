//! The example sessions of SPEC.md and README.md, played over TLS against
//! a whole server, as far as guests can go in M2.
//!
//! The examples are read from the documents themselves, so a change to
//! them that the server does not follow fails here. Only times, the
//! greeting's nonce and the room id change from run to run, and are
//! matched as patterns.

mod common;

use common::{Session, msg, put, readme_example, spec_example};
use risala_proto::types::RoomSetting;
use risala_server::store::EventKind;
use risala_server::testing::TestServer;

/// A server where `#general` is as in the examples: topic "General chat.
/// Be kind.", and 8811 events, the last two from alice and bob.
async fn example_server() -> TestServer {
    TestServer::builder()
        .hostname("chat.example.org")
        .welcome("Welcome!")
        .room("#general")
        .prepare(|store| {
            put(
                store,
                "#general",
                "carol@example.org",
                EventKind::Set(RoomSetting::Topic("General chat. Be kind.".into())),
            );
            for n in 2..=8809 {
                put(
                    store,
                    "#general",
                    "carol@example.org",
                    msg(&format!("message {n}")),
                );
            }
            put(
                store,
                "#general",
                "alice@example.org",
                msg("anyone around?"),
            );
            put(store, "#general", "bob@example.net", msg("yep"));
        })
        .start()
        .await
}

/// Section 1.4, up to the reaction, which needs an identity (M3). Then
/// the `ref` example of 3.6, which reads the same room.
#[tokio::test(flavor = "multi_thread")]
async fn overview_session_and_refs() {
    let server = example_server().await;
    let overview = spec_example("### 1.4. Overview");
    let mut s = Session::new();
    s.add("sam", server.connect().await);
    s.play(&overview.until("OK seq=8813").script()).await;

    // The last line of 1.4 is alice reacting, as an identity. A guest
    // cannot react yet (M4), but a guest joining also makes event 8814,
    // which is what 3.6 needs to report more=1.
    let rest = overview.after("OK seq=8813");
    assert_eq!(rest.lines.len(), 1, "{rest:?}");
    assert!(rest.lines[0].contains(";react=8813 MSG #general"));
    s.add("alice", server.guest("alice").await);
    s.play(
        "alice C: join #general
         alice S: @seq=8814;t={*};from=~alice;id={id} JOIN #general
         alice S: SET #general topic General chat. Be kind.
         alice S: SET #general public yes
         alice S: SET #general guests write
         alice S: SET #general retention server
         alice S: SET #general e2ee no
         alice S: OK id={id} head=8814
         sam S: @seq=8814;t={*};from=~alice;id={id} JOIN #general
         alice C: @react=8813 msg #general 👋
         alice S: ERR not-supported{..}",
    )
    .await;

    s.play(&spec_example("### 3.6. Responses").script()).await;
    s.settled().await;
    server.stop().await;
}

/// The session at the top of README.md.
#[tokio::test(flavor = "multi_thread")]
async fn readme_session() {
    let server = example_server().await;
    let mut s = Session::new();
    s.add("sam", server.connect().await);
    s.play(&readme_example().script()).await;
    s.settled().await;
    server.stop().await;
}

/// Section 1.4 again, with the earlier messages sent live by two guests
/// standing in for alice and bob, who see sam arrive and reply.
#[tokio::test(flavor = "multi_thread")]
async fn overview_session_with_guests() {
    let server = TestServer::builder()
        .hostname("chat.example.org")
        .welcome("Welcome!")
        .room("#general")
        .start()
        .await;
    let mut s = Session::new();
    s.add("sam", server.connect().await);
    s.add("alice", server.guest("alice").await);
    s.add("bob", server.guest("bob").await);
    s.play(
        "alice C: join #general
         alice S: @seq=1;t={*};from=~alice;id={id} JOIN #general
         alice S: SET #general topic
         alice S: SET #general public yes
         alice S: SET #general guests write
         alice S: SET #general retention server
         alice S: SET #general e2ee no
         alice S: OK id={id} head=1
         bob C: join #general
         bob S: @seq=2;t={*};from=~bob;id={id} JOIN #general
         bob S: SET #general topic
         bob S: SET #general public yes
         bob S: SET #general guests write
         bob S: SET #general retention server
         bob S: SET #general e2ee no
         bob S: OK id={id} head=2
         alice S: @seq=2;t={*};from=~bob;id={id} JOIN #general
         alice C: msg #general anyone around?
         alice S: @seq=3;t={*};from=~alice MSG #general anyone around?
         alice S: OK seq=3
         bob S: @seq=3;t={*};from=~alice MSG #general anyone around?
         bob C: msg #general yep
         bob S: @seq=4;t={*};from=~bob MSG #general yep
         bob S: OK seq=4
         alice S: @seq=4;t={*};from=~bob MSG #general yep

         sam S: RISALA 1 chat.example.org {*} Welcome!
         sam C: guest sam
         sam S: OK uid=~sam token={*}
         sam C: join #general
         sam S: @seq=5;t={*};from=~sam;id={id} JOIN #general
         sam S: SET #general topic
         sam S: SET #general public yes
         sam S: SET #general guests write
         sam S: SET #general retention server
         sam S: SET #general e2ee no
         sam S: OK id={id} head=5
         alice S: @seq=5;t={*};from=~sam;id={id} JOIN #general
         bob S: @seq=5;t={*};from=~sam;id={id} JOIN #general
         sam C: history #general before=5 limit=2
         sam S: @seq=3;t={*};from=~alice MSG #general anyone around?
         sam S: @seq=4;t={*};from=~bob MSG #general yep
         sam S: OK id={id} more=1
         sam C: @reply=3 msg #general hi alice, I'm new here
         sam S: @seq=6;t={*};from=~sam;reply=3 MSG #general hi alice, I'm new here
         sam S: OK seq=6
         alice S: @seq=6;t={*};from=~sam;reply=3 MSG #general hi alice, I'm new here
         bob S: @seq=6;t={*};from=~sam;reply=3 MSG #general hi alice, I'm new here",
    )
    .await;
    s.settled().await;
    server.stop().await;
}

/// The sample configuration in README.md's "Running a server" parses.
#[test]
fn readme_sample_config_parses() {
    let section = &common::README[common::README
        .find("## Running a server")
        .expect("README.md has a Running a server section")..];
    let start = section.find("```toml\n").expect("a TOML block") + "```toml\n".len();
    let end = start
        + section[start..]
            .find("\n```")
            .expect("the end of the block");
    let config = risala_server::config::Config::parse(&section[start..end]).unwrap();
    assert_eq!(config.hostname, "chat.example.org");
    assert_eq!(config.tls.certs.len(), 1);
    assert_eq!(config.rooms, ["#general", "#help"]);
}
