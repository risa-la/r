//! TLS for the server (2.1, 2.2): the rustls configuration, certificates
//! chosen by SNI, reloading them from disk, and the generated self-signed
//! certificate of a development server.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use risala_proto::fingerprint::Fingerprint;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::config::{CertPair, Config};

/// The rustls crypto provider: ring, never aws-lc-rs.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The server's TLS configuration (2.1): TLS 1.3 only, the ALPN
/// `risala/1` offered (a client that offers none is still accepted), and
/// certificates chosen by SNI from `certs`.
pub(crate) fn server_config(certs: &Certificates) -> io::Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver(certs.inner.clone())));
    config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
    Ok(config)
}

/// The server's certificates, chosen by SNI and reloadable without
/// dropping connections (2.2).
///
/// Cloning gives another handle to the same set. Connections already open
/// keep the certificate they were set up with; a reload affects only new
/// handshakes.
#[derive(Debug, Clone)]
pub struct Certificates {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    pairs: Vec<CertPair>,
    loaded: RwLock<Vec<Loaded>>,
}

#[derive(Debug, Clone)]
struct Loaded {
    key: Arc<CertifiedKey>,
    fingerprint: Fingerprint,
    /// The files' modification times when last read, successfully or not.
    mtimes: [Option<SystemTime>; 2],
}

impl Certificates {
    /// Loads the certificates in `config.tls.certs`. When there are none,
    /// generates a self-signed certificate for `config.hostname` under
    /// `<state_dir>/selfsigned/`, or reuses the one there, and logs its
    /// fingerprint (2.2).
    ///
    /// Fails if any certificate or key cannot be read, parsed or used, or
    /// if a key does not belong to its certificate.
    pub fn load(config: &Config) -> io::Result<Certificates> {
        let pairs = if config.tls.certs.is_empty() {
            let pair = ensure_self_signed(&config.state_dir, &config.hostname)?;
            vec![pair]
        } else {
            config.tls.certs.clone()
        };
        let loaded = pairs
            .iter()
            .map(load_pair)
            .collect::<io::Result<Vec<_>>>()?;
        if config.tls.certs.is_empty() {
            tracing::info!(
                host = %config.hostname,
                fingerprint = %loaded[0].fingerprint,
                "using a self-signed certificate"
            );
        }
        Ok(Certificates {
            inner: Arc::new(Inner {
                pairs,
                loaded: RwLock::new(loaded),
            }),
        })
    }

    /// The fingerprint of the first certificate, the one a client gets
    /// when it sends no SNI (2.2).
    pub fn fingerprint(&self) -> Fingerprint {
        self.read()[0].fingerprint
    }

    /// The fingerprints of every certificate, in configuration order.
    pub fn fingerprints(&self) -> Vec<Fingerprint> {
        self.read().iter().map(|l| l.fingerprint).collect()
    }

    /// Re-reads every certificate and key (2.2). A pair that fails to load
    /// keeps its old certificate, and the error is logged. Returns whether
    /// every pair loaded.
    ///
    /// This reads files, so call it from a blocking context.
    pub fn reload(&self) -> bool {
        self.reload_where(|_, _| true)
    }

    /// Re-reads the pairs whose files changed on disk since they were last
    /// read, judged by modification time. Returns whether every pair that
    /// was re-read loaded.
    ///
    /// This reads files, so call it from a blocking context.
    pub fn reload_if_changed(&self) -> bool {
        self.reload_where(|pair, old| mtimes(pair) != old.mtimes)
    }

    fn reload_where(&self, mut changed: impl FnMut(&CertPair, &Loaded) -> bool) -> bool {
        let current = self.read().clone();
        let mut next = current.clone();
        let mut ok = true;
        let mut any = false;
        for ((pair, old), slot) in self.inner.pairs.iter().zip(&current).zip(&mut next) {
            if !changed(pair, old) {
                continue;
            }
            any = true;
            match load_pair(pair) {
                Ok(new) => {
                    tracing::info!(
                        cert = %pair.cert.display(),
                        fingerprint = %new.fingerprint,
                        "loaded certificate"
                    );
                    *slot = new;
                }
                Err(e) => {
                    ok = false;
                    tracing::error!(
                        cert = %pair.cert.display(),
                        error = %e,
                        "could not reload certificate, keeping the old one"
                    );
                    // Remember the times, so a broken file is reported once
                    // per change rather than at every poll.
                    slot.mtimes = mtimes(pair);
                }
            }
        }
        if any {
            *self.inner.loaded.write().unwrap_or_else(|e| e.into_inner()) = next;
        }
        ok
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Vec<Loaded>> {
        self.inner.loaded.read().unwrap_or_else(|e| e.into_inner())
    }
}

/// Chooses a certificate by SNI: the first whose certificate is valid for
/// the name, or else the first one (2.1).
#[derive(Debug)]
struct Resolver(Arc<Inner>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let loaded = self.0.loaded.read().unwrap_or_else(|e| e.into_inner());
        if let Some(name) = hello
            .server_name()
            .and_then(|s| ServerName::try_from(s).ok())
        {
            let chosen = loaded.iter().find(|l| {
                l.key.end_entity_cert().is_ok_and(|der| {
                    webpki::EndEntityCert::try_from(der)
                        .and_then(|cert| cert.verify_is_valid_for_subject_name(&name))
                        .is_ok()
                })
            });
            if let Some(l) = chosen {
                return Some(l.key.clone());
            }
        }
        loaded.first().map(|l| l.key.clone())
    }
}

fn mtimes(pair: &CertPair) -> [Option<SystemTime>; 2] {
    let mtime = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    [mtime(&pair.cert), mtime(&pair.key)]
}

fn invalid(path: &Path, what: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {what}", path.display()),
    )
}

/// Reads one certificate chain and its key.
fn load_pair(pair: &CertPair) -> io::Result<Loaded> {
    // Read the times first: a file replaced while it is being read then
    // looks changed at the next poll, and is read again.
    let mtimes = mtimes(pair);
    let chain = CertificateDer::pem_file_iter(&pair.cert)
        .map_err(|e| invalid(&pair.cert, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| invalid(&pair.cert, e))?;
    if chain.is_empty() {
        return Err(invalid(&pair.cert, "no certificate in the file"));
    }
    let fingerprint = spki_fingerprint(&chain[0]).map_err(|e| invalid(&pair.cert, e))?;
    let key = PrivateKeyDer::from_pem_file(&pair.key).map_err(|e| invalid(&pair.key, e))?;
    let key = CertifiedKey::from_der(chain, key, &provider()).map_err(|e| invalid(&pair.key, e))?;
    Ok(Loaded {
        key: Arc::new(key),
        fingerprint,
        mtimes,
    })
}

/// The fingerprint of a certificate: the SHA-256 hash of its
/// SubjectPublicKeyInfo (2.2), as Appendix A's openssl pipeline prints it.
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> Result<Fingerprint, webpki::Error> {
    let cert = webpki::EndEntityCert::try_from(cert)?;
    Ok(Fingerprint::from_spki_der(&cert.subject_public_key_info()))
}

/// Where the generated self-signed certificate lives: its chain and its
/// key, under `<state_dir>/selfsigned/`.
pub fn self_signed_paths(state_dir: &Path) -> CertPair {
    let dir = state_dir.join("selfsigned");
    CertPair {
        cert: dir.join("cert.pem"),
        key: dir.join("key.pem"),
    }
}

/// Makes sure a self-signed certificate for `hostname` exists under
/// `<state_dir>/selfsigned/` and returns its paths.
///
/// The key is made once and kept, so the fingerprint, which pins the key
/// (2.2), stays the same across restarts. The certificate is issued again
/// with the same key if it is missing, unreadable or not valid for
/// `hostname`.
fn ensure_self_signed(state_dir: &Path, hostname: &str) -> io::Result<CertPair> {
    let pair = self_signed_paths(state_dir);
    let dir = pair.cert.parent().expect("the paths are in a directory");
    fs::create_dir_all(dir)?;

    let key = match fs::read_to_string(&pair.key) {
        Ok(pem) => rcgen::KeyPair::from_pem(&pem).map_err(|e| invalid(&pair.key, e))?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = rcgen::KeyPair::generate().map_err(io::Error::other)?;
            write_atomic(&pair.key, key.serialize_pem().as_bytes(), true)?;
            tracing::info!(key = %pair.key.display(), "generated a key for the self-signed certificate");
            key
        }
        Err(e) => return Err(e),
    };

    if !self_signed_cert_fits(&pair, hostname) {
        let mut params =
            rcgen::CertificateParams::new(vec![hostname.to_owned()]).map_err(io::Error::other)?;
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, hostname);
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).map_err(io::Error::other)?;
        write_atomic(&pair.cert, cert.pem().as_bytes(), false)?;
        tracing::info!(cert = %pair.cert.display(), host = hostname, "issued a self-signed certificate");
    }
    Ok(pair)
}

/// Whether the stored self-signed certificate can be used as it is: it
/// loads with its key and is valid for `hostname`.
fn self_signed_cert_fits(pair: &CertPair, hostname: &str) -> bool {
    let Ok(loaded) = load_pair(pair) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(hostname) else {
        return false;
    };
    loaded.key.end_entity_cert().is_ok_and(|der| {
        webpki::EndEntityCert::try_from(der)
            .and_then(|cert| cert.verify_is_valid_for_subject_name(&name))
            .is_ok()
    })
}

/// Writes a file through a temporary one and a rename, so a reader never
/// sees half of it. A private file gets mode 0600 on Unix.
fn write_atomic(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    use std::io::Write as _;

    let mut tmp = PathBuf::from(path);
    tmp.as_mut_os_string().push(".tmp");
    // A leftover file would keep its old mode, so start afresh.
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)
}
