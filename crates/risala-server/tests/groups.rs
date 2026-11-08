//! Encrypted conversations over TLS against a whole server (Section 12):
//! KeyPackages uploaded with KEYPKG ADD and fetched with KEYPKG GET, a
//! direct conversation and an encrypted room made with INIT and COMMIT,
//! joined by Welcome, with ENC both ways. The devices are OpenMLS clients
//! built with `risala-mls`, as librisala's are. The hub's own tests
//! (`src/core/group_tests.rs`) cover each rule.

mod common;

use common::command;
use openmls_memory_storage::MemoryStorage;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::{KeyPackageIn, ProcessedMessageContent, ProtocolVersion};
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::{Changes, DeviceSigner, HistoryKey, Provider, RisalaConversation, wire};
use risala_proto::mls;
use risala_proto::types::{HistoryMode, SendMode};
use risala_server::testing::{TestClient, TestIdentity, TestServer};

/// A server that hosts `example.org`, and lets identities at
/// `example.net` sign in.
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net"])
        .start()
        .await
}

/// A device: an identity's key, its MLS state, and its connection.
struct Device {
    who: TestIdentity,
    provider: Provider<MemoryStorage>,
    conn: TestClient,
}

impl Device {
    async fn new(server: &TestServer, who: TestIdentity) -> Device {
        let conn = server.sign_in(&who).await;
        Device {
            who,
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            conn,
        }
    }

    fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner::new(self.who.key())
    }

    async fn send(&mut self, line: &str) -> Vec<String> {
        command(&mut self.conn, line).await
    }

    /// Uploads a KeyPackage with KEYPKG ADD (12.4).
    async fn upload_key_package(&mut self) {
        let bundle =
            risala_mls::key_package(&self.provider, &self.signer(), &self.who.uid(), false)
                .unwrap();
        let kp = wire::key_package_to_wire(bundle.key_package()).unwrap();
        assert_eq!(self.send(&format!("keypkg add {kp}")).await, ["OK"]);
    }

    /// The KeyPackages of `uid`'s devices, from KEYPKG GET (12.4).
    async fn key_packages(&mut self, uid: &str) -> Vec<risala_mls::openmls::prelude::KeyPackage> {
        let lines = self.send(&format!("keypkg get {uid}")).await;
        assert_eq!(lines.last().unwrap(), "OK");
        lines[..lines.len() - 1]
            .iter()
            .map(|line| {
                let kp: mls::KeyPackage = line.rsplit(' ').next().unwrap().parse().unwrap();
                let kp: KeyPackageIn = wire::key_package_from_wire(&kp).unwrap();
                kp.validate(self.provider.crypto(), ProtocolVersion::Mls10)
                    .unwrap()
            })
            .collect()
    }

    /// INIT of a new group for `conv`. Returns the reply and the group.
    async fn init(
        &mut self,
        conv: &str,
        extension: &RisalaConversation,
    ) -> (Vec<String>, MlsGroup) {
        let group =
            risala_mls::create_group(&self.provider, &self.signer(), &self.who.uid(), extension)
                .unwrap();
        let gi = group
            .export_group_info(self.provider.crypto(), &self.signer(), false)
            .unwrap();
        let gi = wire::group_info_to_wire(&gi).unwrap();
        let tree = wire::tree_to_wire(&group.export_ratchet_tree()).unwrap();
        (self.send(&format!("init {conv} {gi} {tree}")).await, group)
    }

    /// COMMIT of `changes`, merged once accepted. Returns the reply.
    async fn commit(&mut self, conv: &str, group: &mut MlsGroup, changes: Changes) -> Vec<String> {
        let bundle = risala_mls::commit(&self.provider, group, &self.signer(), changes).unwrap();
        let (commit, welcome, gi) = bundle.into_messages();
        let commit = wire::commit_to_wire(&commit).unwrap();
        let gi = wire::group_info_to_wire(&gi.unwrap()).unwrap();
        let line = match welcome {
            Some(w) => format!(
                "commit {conv} {commit} {gi} {}",
                wire::welcome_to_wire(&w).unwrap()
            ),
            None => format!("commit {conv} {commit} {gi}"),
        };
        let lines = self.send(&line).await;
        assert!(lines.last().unwrap().starts_with("OK seq="), "{lines:?}");
        group.merge_pending_commit(&self.provider).unwrap();
        lines
    }

    /// Reads lines until one starts with `start` once its tags are gone.
    async fn until(&mut self, start: &str) -> String {
        loop {
            let line = common::recv(&mut self.conn).await;
            if untagged(&line).starts_with(start) {
                return line;
            }
        }
    }

    /// Joins by the Welcome of a WELCOME line, and deletes it (12.7).
    async fn join(&mut self, line: &str) -> MlsGroup {
        let parts: Vec<&str> = untagged(line).split(' ').collect();
        let welcome: mls::Welcome = parts[4].parse().unwrap();
        let tree: mls::RatchetTree = parts[5].parse().unwrap();
        let group = risala_mls::stage_welcome(
            &self.provider,
            wire::welcome_from_wire(&welcome).unwrap(),
            wire::tree_from_wire(&tree).unwrap(),
        )
        .unwrap()
        .into_group(&self.provider)
        .unwrap();
        assert_eq!(
            self.send(&format!("welcome del {}", parts[2])).await,
            ["OK"]
        );
        group
    }

    /// Applies the commit of a COMMIT event line.
    fn apply(&self, group: &mut MlsGroup, line: &str) {
        let commit: mls::CommitMessage = line.rsplit(' ').next().unwrap().parse().unwrap();
        let processed = group
            .process_message(&self.provider, wire::commit_from_wire(&commit).unwrap())
            .unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        group.merge_staged_commit(&self.provider, *staged).unwrap();
    }

    /// An ENC line with `content` in the group's current epoch (12.8).
    fn enc(&self, conv: &str, group: &MlsGroup, content: &str) -> String {
        let key = HistoryKey::of_group(group, self.provider.crypto()).unwrap();
        let epoch = group.epoch().as_u64();
        let sent = risala_mls::encrypt(
            &self.signer(),
            &key,
            group.group_id().as_slice(),
            epoch,
            content.as_bytes(),
        )
        .unwrap();
        format!("@frank={} enc {conv} {epoch} {}", sent.frank, sent.payload)
    }

    /// The content of an ENC event line, checked against the group's
    /// leaves (12.8).
    fn read(&self, group: &MlsGroup, line: &str) -> String {
        let frank: mls::Frank = line
            .split(";frank=")
            .nth(1)
            .and_then(|rest| rest.split([' ', ';']).next())
            .unwrap()
            .parse()
            .unwrap();
        let payload: mls::Ciphertext = line.rsplit(' ').next().unwrap().parse().unwrap();
        let key = HistoryKey::of_group(group, self.provider.crypto()).unwrap();
        let unverified = risala_mls::decrypt(
            &key,
            group.group_id().as_slice(),
            group.epoch().as_u64(),
            &payload,
            &frank,
        )
        .unwrap();
        let leaves: Vec<_> = group
            .members()
            .map(|m| risala_mls::signer::signature_key(&m.signature_key).unwrap())
            .collect();
        let sender = unverified.find_sender(&leaves).unwrap().clone();
        String::from_utf8(unverified.verify(&sender).unwrap().content).unwrap()
    }
}

/// A line without its tags.
fn untagged(line: &str) -> &str {
    match line.strip_prefix('@') {
        Some(rest) => rest.split_once(' ').map_or(rest, |(_, l)| l),
        None => line,
    }
}

/// Alice starts a direct conversation with Bob, adds his device and her
/// own second one, and they talk (12.6).
#[tokio::test]
async fn a_direct_conversation_over_the_wire() {
    let server = server().await;
    let (alice, _) = server.register("alice").await;
    let phone = server.new_device(&alice).await;
    let bob = server.key_server().new_identity("bob@example.net");
    let mut a1 = Device::new(&server, alice).await;
    let mut a2 = Device::new(&server, phone).await;
    let mut b1 = Device::new(&server, bob).await;
    b1.upload_key_package().await;
    a2.upload_key_package().await;

    let extension = RisalaConversation::direct(&a1.who.uid(), &b1.who.uid());
    let (lines, mut ga) = a1.init("bob@example.net", &extension).await;
    assert!(lines[0].starts_with("OK id="), "{lines:?}");
    let mut add = a1.key_packages("bob@example.net").await;
    add.extend(a1.key_packages("alice@example.org").await);
    assert_eq!(add.len(), 2);
    let lines = a1
        .commit(
            "bob@example.net",
            &mut ga,
            Changes {
                add,
                ..Changes::default()
            },
        )
        .await;
    assert!(untagged(&lines[0]).starts_with("COMMIT bob@example.net 1 "));

    // Each added device gets the COMMIT event and its Welcome, live.
    b1.until("COMMIT alice@example.org 1 ").await;
    let welcome = b1.until("WELCOME alice@example.org ").await;
    let gb = b1.join(&welcome).await;
    a2.until("COMMIT bob@example.net 1 ").await;
    let welcome = a2.until("WELCOME bob@example.net ").await;
    let ga2 = a2.join(&welcome).await;

    let line = b1.enc("alice@example.org", &gb, "TEXT hello alice\n");
    let lines = b1.send(&line).await;
    assert_eq!(lines.last().unwrap(), "OK seq=2");
    let event = a1.until("ENC bob@example.net 1 ").await;
    assert_eq!(a1.read(&ga, &event), "TEXT hello alice\n");
    let event = a2.until("ENC bob@example.net 1 ").await;
    assert_eq!(a2.read(&ga2, &event), "TEXT hello alice\n");

    // A device catching up reads the commits alone first (12.11).
    let lines = a2.send("history bob@example.net after=0 only=commit").await;
    assert_eq!(lines.len(), 2);
    assert!(untagged(&lines[0]).starts_with("COMMIT bob@example.net 1 "));
    server.stop().await;
}

/// Alice encrypts a room, invites Bob by adding his device, and he joins
/// it (12.3, 12.6).
#[tokio::test]
async fn an_encrypted_room_over_the_wire() {
    let server = server().await;
    let (alice, _) = server.register("alice").await;
    let bob = server.key_server().new_identity("bob@example.net");
    let mut a1 = Device::new(&server, alice).await;
    let mut b1 = Device::new(&server, bob).await;
    b1.upload_key_package().await;

    let lines = a1.send("join #secret").await;
    let id = common::value(lines.last().unwrap(), "id");
    let extension =
        RisalaConversation::room(&id.parse().unwrap(), HistoryMode::Joined, SendMode::All);
    let (lines, mut ga) = a1.init("#secret", &extension).await;
    assert_eq!(lines.last().unwrap(), &format!("OK id={id} epoch=0"));
    assert!(lines.iter().any(|l| untagged(l) == "SET #secret e2ee yes"));

    let add = a1.key_packages("bob@example.net").await;
    let lines = a1
        .commit(
            "#secret",
            &mut ga,
            Changes {
                add,
                ..Changes::default()
            },
        )
        .await;
    assert_eq!(untagged(&lines[1]), "INVITE #secret bob@example.net");
    b1.until("INVITE #secret bob@example.net").await;
    let welcome = b1.until("WELCOME #secret ").await;
    let mut gb = b1.join(&welcome).await;
    let lines = b1.send("join #secret").await;
    assert!(untagged(&lines[0]).starts_with("JOIN #secret"), "{lines:?}");

    // Alice refreshes her leaf; Bob applies the commit, and they talk.
    a1.commit("#secret", &mut ga, Changes::default()).await;
    let commit = b1.until("COMMIT #secret 2 ").await;
    b1.apply(&mut gb, &commit);
    let lines = a1.send(&a1.enc("#secret", &ga, "TEXT welcome\n")).await;
    assert!(lines.last().unwrap().starts_with("OK seq="));
    let event = b1.until("ENC #secret 2 ").await;
    assert_eq!(b1.read(&gb, &event), "TEXT welcome\n");

    // MSG is refused, and so is a join without an invitation.
    assert_eq!(
        b1.send("msg #secret hi").await,
        ["ERR encrypted send with ENC"]
    );
    let carol = server.key_server().new_identity("carol@example.net");
    let mut c1 = Device::new(&server, carol).await;
    assert_eq!(
        c1.send("join #secret").await,
        ["ERR not-found no such room"]
    );
    server.stop().await;
}
