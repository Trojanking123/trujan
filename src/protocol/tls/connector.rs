use crate::protocol::{Address, DummyUdpStream, ProxyConnector, ProxyTcpStream};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector, rustls::{RootCertStore, OwnedTrustAnchor, ServerName}};
use webpki::TrustAnchor;
use super::get_cipher_suite;

#[derive(Deserialize)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_config: Arc<ClientConfig>,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig) -> io::Result<Self> {
        let mut  root_certs = RootCertStore::empty();
        
        if let Some(ref cert_path) = config.cert {
            let cert_path = Path::new(cert_path);
            let res = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
                                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert")).unwrap();
            //let certs: Vec<Certificate> = res.into_iter().map(& |v| Certificate(v)).collect();
            root_certs.add_parsable_certificates(res.as_slice());
  
        } else {
            let ta: Vec<OwnedTrustAnchor> = webpki_roots::TLS_SERVER_ROOTS.0.into_iter().map(& |v: &TrustAnchor| {
               OwnedTrustAnchor::from_subject_spki_name_constraints(v.subject, v.spki, v.name_constraints)
                
            }).collect();
            root_certs.add_server_trust_anchors(ta.into_iter());
        }
        
        let cipher_suites = get_cipher_suite( config.cipher.clone() ).unwrap();

        let tls_config = ClientConfig::builder()
                                                    .with_cipher_suites(cipher_suites.as_slice())
                                                    .with_safe_default_kx_groups()
                                                    .with_safe_default_protocol_versions()
                                                    .unwrap()
                                                    .with_root_certificates(root_certs)
                                                    .with_no_client_auth();



        Ok(Self {
            sni: config.sni.clone(),
            server_addr: config.addr.clone(),
            tls_config: Arc::new(tls_config),
        })
    }
}

#[async_trait]
impl ProxyConnector for TrojanTlsConnector {
    type TS = TlsStream<TcpStream>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, _: &Address) -> io::Result<Self::TS> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;
        use std::convert::TryFrom;
        let dns_name = ServerName::try_from(self.sni.as_str())
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?;

        let stream = TlsConnector::from(self.tls_config.clone())
            .connect(dns_name, stream)
            .await?;

        log::info!("connected to {}", self.server_addr);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        unimplemented!()
    }
}
