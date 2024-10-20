use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, str::FromStr, sync::Arc};

use anyhow::{bail, Context, Error};
use base64::prelude::*;
use ini::Ini;
use onetun::{config::{Config, PortForwardConfig}, events::Bus, tunnel::tcp::TcpPortPool, wg::WireGuardTunnel};
use tokio::net::{TcpSocket, TcpStream};
use tokio_socks::tcp::Socks5Stream;

#[derive(Debug, Clone)]
pub(crate) struct SocksProxyConfig {
    pub host: String,
    pub port: u16,
    pub username_password: Option<(String, String)>,
}

impl ProxyConfigTrait for SocksProxyConfig {
    async fn parse(s: &str) -> anyhow::Result<Self> {
        let url = ::url::Url::parse(s).context("invalid proxy URL")?;
        if url.scheme() != "socks5" {
            anyhow::bail!("proxy URL should have socks5 scheme");
        }
        let host = url.host_str().context("missing host")?;
        let port = url.port().context("missing port")?;
        let up = url
            .password()
            .map(|p| (url.username().to_owned(), p.to_owned()));
        Ok(Self {
            host: host.to_owned(),
            port,
            username_password: up,
        })
    }

    async fn connect(
        &self,
        addr: SocketAddr,
    ) -> anyhow::Result<ProxyConfigTcpStream> {
        let proxy_addr = (self.host.as_str(), self.port);

        if let Some((username, password)) = self.username_password.as_ref() {
            Ok(ProxyConfigTcpStream::Socks5Stream(tokio_socks::tcp::Socks5Stream::connect_with_password(
                proxy_addr,
                addr,
                username.as_str(),
                password.as_str(),
            )
            .await
            .context("error connecting to proxy").unwrap()))
        } else {
            Ok(ProxyConfigTcpStream::Socks5Stream(tokio_socks::tcp::Socks5Stream::connect(proxy_addr, addr)
                .await
                .context("error connecting to proxy").unwrap()))
        }
    }
}

#[derive(Clone)]
pub(crate) struct WireguardProxyConfig {
    pub priv_key: [u8;32],
    pub pub_key: [u8;32],
    pub endpoint: SocketAddr,
    wg: Arc<WireGuardTunnel>,
    tcp_port_pool: TcpPortPool,
    bus: Bus,
}
#[derive(Debug)]
pub(crate) struct ConfigWireguardPeer {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<String>,
    pub endpoint: String,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug)]
pub(crate) struct ConfigWireGuard {
    pub private_key: [u8; 32],
    pub address: Vec<String>,
    pub listen_port: Option<u16>,
    pub peers: Vec<ConfigWireguardPeer>,
}

impl WireguardProxyConfig {

    async fn from_str(s: &str) -> Result<Self, Error> {
        let conf = match Ini::load_from_str(s) {
            Ok(conf) => conf,
            Err(_) => anyhow::bail!("failed to load wireguard config from string"),
        };

        // Parse Interface section
        let interface = match conf.section(Some("Interface")) {
            Some(interface) => interface,
            None => anyhow::bail!("Missing Interface section"),
        };

        let private_key = match interface.get("PrivateKey") {
            Some(private_key) => {
                let mut pk_bytes: [u8; 32] = [0u8; 32];
                BASE64_STANDARD
                    .decode_slice(private_key, &mut pk_bytes)
                    .unwrap();
                pk_bytes
            }
            None => anyhow::bail!("Missing PrivateKey"),
        };

        let address = match interface.get("Address") {
            Some(addrs) => addrs.split(',').map(|s| s.trim().to_string()).collect::<Vec<String>>(),
            None => anyhow::bail!("Missing Address"),
        };

        let listen_port = match interface
            .get("ListenPort")
            .map(|p| p.parse::<u16>())
            .transpose()
        {
            Ok(listen_port) => listen_port,
            Err(_) => None,
        };

        // Parse Peer sections
        let mut peers = Vec::new();
        for (section_name, section) in conf.iter() {
            if section_name.map_or(false, |name| name.starts_with("Peer")) {
                let peer = ConfigWireguardPeer {
                    public_key: match section.get("PublicKey") {
                        Some(public_key) => {
                            let mut pk_slice: [u8; 32] = [0u8; 32];
                            BASE64_STANDARD
                                .decode_slice(public_key, &mut pk_slice)
                                .unwrap();
                            pk_slice
                        }
                        None => anyhow::bail!("Missing PublicKey in Peer"),
                    },
                    allowed_ips: match section.get("AllowedIPs") {
                        Some(allowed_ips) => allowed_ips
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect::<Vec<String>>(),
                        None => anyhow::bail!("Missing AllowedIPs in Peer"),
                    },
                    endpoint: match section.get("Endpoint").map(String::from) {
                        Some(endpoint) => endpoint,
                        None => anyhow::bail!("Missing Endpoint in Peer"),
                    },
                    persistent_keepalive: section
                        .get("PersistentKeepalive")
                        .map(|v| v.parse::<u16>())
                        .transpose()?,
                };
                peers.push(peer);
            }
        }

        let peer = peers.first().unwrap();
        let endpoint = SocketAddr::from_str(&peer.endpoint.clone()).unwrap();
        let pf = PortForwardConfig {
            source: SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap()),
                0,
            ),
            destination: SocketAddr::from_str("1.1.1.1:80").unwrap(),
            protocol: onetun::config::PortProtocol::Tcp,
            remote: true,
        };
        let config = Config {
            port_forwards: vec![pf.clone()],
            remote_port_forwards: vec![pf.clone()],
            private_key: Arc::new(onetun::config::StaticSecret::from(private_key.clone())),
            endpoint_public_key: Arc::new(onetun::config::PublicKey::from(peer.public_key.clone())),
            preshared_key: None,
            endpoint_addr: endpoint,
            endpoint_bind_addr: SocketAddr::new(IpAddr::from_str("0.0.0.0").unwrap(), 0),
            source_peer_ip: IpAddr::from_str("10.72.37.77").unwrap(),
            keepalive_seconds: Some(15),
            max_transmission_unit: 1420,
            log: "".to_string(),
            warnings: vec![],
            pcap_file: None,
        };

        let bus = Bus::default();
        let (tcp_port_pool, wg) = onetun::start_wg_tcp_only(&config, &bus).await.unwrap();
        
        Ok(Self {
            priv_key: private_key.clone(),
            pub_key: peer.public_key.clone(),
            endpoint: endpoint,
            wg: wg,
            tcp_port_pool: tcp_port_pool,
            bus: bus,
        })
    }
}

impl ProxyConfigTrait for WireguardProxyConfig {
    
    async fn parse(s: &str) -> anyhow::Result<Self> {
        WireguardProxyConfig::from_str(&s).await
    }

    async fn connect(
        &self,
        addr: SocketAddr,
    ) -> anyhow::Result<ProxyConfigTcpStream,Error> {
        let vport = self.tcp_port_pool.next().await.unwrap();
        let pf = PortForwardConfig {
            source: SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            destination: addr,
            protocol: onetun::config::PortProtocol::Tcp,
            remote: true,
        };
        Ok(ProxyConfigTcpStream::TcpStream(onetun::tunnel::tcp::new_tcp_proxy_connection(vport, pf, self.bus.clone()).await.unwrap()))
    }

}

pub enum ProxyConfig {
    SocksProxyConfig(SocksProxyConfig),
    WireguardProxyConfig(WireguardProxyConfig),
}

enum ProxyConfigTcpStream {
    Socks5Stream(Socks5Stream<TcpStream>),
    TcpStream(TcpStream),
}

pub trait ProxyConfigTrait {
    async fn connect(
        &self,
        addr: SocketAddr,
    ) -> anyhow::Result<ProxyConfigTcpStream>;
    async fn parse(s: &str) -> anyhow::Result<Self> where Self: Sized;
}

#[derive(Default)]
pub(crate) struct StreamConnector {
    proxy_config: Option<ProxyConfig>,
}

impl From<Option<ProxyConfig>> for StreamConnector {
    fn from(proxy_config: Option<ProxyConfig>) -> Self {
        Self { proxy_config: Some(proxy_config.unwrap()) }
    }
}

impl From<Option<SocksProxyConfig>> for StreamConnector {
    fn from(proxy_config: Option<SocksProxyConfig>) -> Self {
        Self { proxy_config: Some(ProxyConfig::SocksProxyConfig(proxy_config.unwrap())) }
    }
}

impl From<Option<WireguardProxyConfig>> for StreamConnector {
    fn from(proxy_config: Option<WireguardProxyConfig>) -> Self {
        Self { proxy_config: Some(ProxyConfig::WireguardProxyConfig(proxy_config.unwrap())) }
    }
}

pub(crate) trait AsyncReadWrite:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin
{
}

impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}



impl StreamConnector {
    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        match self.proxy_config.as_ref() {
            Some(proxy_config) => match proxy_config {
                ProxyConfig::SocksProxyConfig(proxy_config)  =>     {
                    let tcp_stream = proxy_config.connect(addr).await.unwrap();
                    match tcp_stream {
                        ProxyConfigTcpStream::Socks5Stream(socks_stream) => Ok(Box::new(socks_stream)),
                        _ => unreachable!(),
                    }
                    
                },
                ProxyConfig::WireguardProxyConfig(proxy_config) => {
                    let tcp_stream = proxy_config.connect(addr).await.unwrap();
                    match tcp_stream {
                        ProxyConfigTcpStream::TcpStream(tcp_stream) => Ok(Box::new(tcp_stream)),
                        _ => unreachable!(),
                    }
                },
            },
            None => {
                println!("failed to connect streaconnector");
                bail!("failed to connect streaconnector")
            },
        }
    }
}
