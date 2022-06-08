use tokio_rustls::rustls::{
    Certificate, CipherSuite, PrivateKey, SupportedCipherSuite, ALL_CIPHER_SUITES,
};
use rustls_pemfile;

use crate::error::Error;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    return Error::new(format!("tls: {}", message.to_string())).into();
}

fn load_cert(path: &Path) -> io::Result<Vec<Certificate>> {
    let res = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert")).unwrap();
    let certs = res.into_iter().map(& |v| Certificate(v)).collect();
    Ok(certs)
    

}

fn load_key(path: &Path) -> io::Result<Vec<PrivateKey>> {
    let pkcs8_key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls pkcs8 key"))?;
    if pkcs8_key.len() != 0 {
        let keys = pkcs8_key.into_iter().map(& |v| PrivateKey(v)).collect();
        return Ok(keys);
    }
    let rsa_key = rustls_pemfile::rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls rsa key"))?;
    if rsa_key.len() != 0 {
        let keys = rsa_key.into_iter().map(& |v| PrivateKey(v)).collect();
        return Ok(keys);
    }
    return Err(new_error("no valid key found"));
}

fn get_cipher_name(cipher: &SupportedCipherSuite) -> &'static str {
    /*
    /// A list of all the cipher suites supported by rustls.
    pub static ALL_CIPHER_SUITES: [&SupportedCipherSuite; 9] = [
        // TLS1.3 suites
        &TLS13_CHACHA20_POLY1305_SHA256,
        &TLS13_AES_256_GCM_SHA384,
        &TLS13_AES_128_GCM_SHA256,

        // TLS1.2 suites
        &TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        &TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
     */
    match cipher.suite() {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS13_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS13_AES_256_GCM_SHA384",
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS13_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
        _ => "???",
    }
}

fn get_cipher_suite(cipher: Option<Vec<String>>) -> io::Result<Vec< SupportedCipherSuite>> {
    if cipher.is_none() {
        return Ok(ALL_CIPHER_SUITES.to_vec());
    }
    let cipher = cipher.unwrap();
    let mut result = Vec::new();

    for name in cipher {
        let mut found = false;
        for i in ALL_CIPHER_SUITES.to_vec() {
            if name == get_cipher_name(&i) {
                result.push(i);
                found = true;
                log::debug!("cipher: {} applied", name);
                break;
            }
        }
        if !found {
            return Err(new_error(format!("bad cipher: {}", name)));
        }
    }
    Ok(result)
}
