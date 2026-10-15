//! Throw-away PKI for tests (feature `test-support`): a CA, a server certificate for
//! `localhost`/`127.0.0.1`, and any number of client certificates.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};

use crate::identity::fingerprint_of;

pub struct TestPki {
    ca: rcgen::Certificate,
    ca_key: KeyPair,
    pub ca_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
    /// SHA-256 of the DER certificate, as the IdentityMap expects it.
    pub fingerprint: String,
}

impl Default for TestPki {
    fn default() -> Self {
        Self::new()
    }
}

impl TestPki {
    pub fn new() -> TestPki {
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::new()).unwrap();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name
            .push(DnType::CommonName, "janus test CA");
        let ca = p.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut sp = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        sp.subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        sp.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = sp.signed_by(&server_key, &ca, &ca_key).unwrap();

        TestPki {
            ca_pem: ca.pem(),
            server_cert_pem: server.pem(),
            server_key_pem: server_key.serialize_pem(),
            ca,
            ca_key,
        }
    }

    pub fn issue_client(&self, name: &str) -> ClientIdentity {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.signed_by(&key, &self.ca, &self.ca_key).unwrap();
        ClientIdentity {
            fingerprint: fingerprint_of(cert.der().as_ref()),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// Server side files (`server.pem`, `server.key`, `ca.pem`) for `TlsPaths`.
    pub fn write_server_files(&self, dir: &Path) -> crate::tls::TlsPaths {
        std::fs::create_dir_all(dir).unwrap();
        let paths = crate::tls::TlsPaths {
            cert: dir.join("server.pem"),
            key: dir.join("server.key"),
            ca: dir.join("ca.pem"),
        };
        write_private(&paths.cert, &self.server_cert_pem);
        write_private(&paths.key, &self.server_key_pem);
        write_private(&paths.ca, &self.ca_pem);
        paths
    }
}

impl ClientIdentity {
    /// Returns `(cert_path, key_path)`.
    pub fn write_files(&self, dir: &Path, stem: &str) -> (String, String) {
        std::fs::create_dir_all(dir).unwrap();
        let (c, k) = (
            dir.join(format!("{stem}.pem")),
            dir.join(format!("{stem}.key")),
        );
        write_private(&c, &self.cert_pem);
        write_private(&k, &self.key_pem);
        (c.display().to_string(), k.display().to_string())
    }
}

fn write_private(path: &Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
