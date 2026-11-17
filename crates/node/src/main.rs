use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use core_node::{Config, Node, NodeIdentity, Store};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

const CONFIG_FILE: &str = "node.toml";
const IDENTITY_FILE: &str = "identity.toml";
const DB_FILE: &str = "node.db";

#[derive(Parser)]
#[command(name = "core-node", version, about = "CORE network node")]
struct Cli {
    /// Каталог с ключами, конфигом и базой.
    #[arg(long, env = "CORE_DATA_DIR", default_value = "./node-data", global = true)]
    data_dir: PathBuf,

    /// Переопределить `listen` из конфига.
    #[arg(long, env = "CORE_LISTEN", global = true)]
    listen: Option<String>,

    /// Переопределить `public_host` (host:port, который увидят клиенты).
    #[arg(long, env = "CORE_PUBLIC_HOST", global = true)]
    public_host: Option<String>,

    /// Дополнительные host:port в дескрипторе ноды (через запятую).
    #[arg(long, env = "CORE_EXTRA_ADDRESSES", value_delimiter = ',', global = true)]
    extra_addresses: Option<Vec<String>>,

    /// Bootstrap-ноды `core://…` (через запятую).
    #[arg(long, env = "CORE_BOOTSTRAP", value_delimiter = ',', global = true)]
    bootstrap: Option<Vec<String>>,

    /// Брать соседей из общего списка нод: URL списка или `1` / `true` — список сети CORE по умолчанию.
    /// Нода сама выберет ближайшие по задержке и будет пересматривать их.
    #[arg(long, env = "GIT_NODES", global = true)]
    git_nodes: Option<String>,

    /// Имя ноды для карты сети.
    #[arg(long, env = "CORE_NAME", global = true)]
    name: Option<String>,

    /// Код страны для карты сети.
    #[arg(long, env = "CORE_REGION", global = true)]
    region: Option<String>,

    /// ТОЛЬКО ДЛЯ TESTNET: детерминированные ключи из строки (адрес известен заранее).
    #[arg(long, env = "CORE_IDENTITY_SEED", global = true, hide_env_values = true)]
    identity_seed: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Создать каталог, ключи и конфиг по умолчанию.
    Init,
    /// Запустить ноду (ключи и конфиг создаются при первом запуске).
    Run,
    /// Показать ID и адрес ноды.
    Info,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let (config, identity) = prepare(&cli)?;

    match cli.command {
        Command::Init | Command::Info => {
            print_info(&identity, &identity.address(config.advertised_host()).to_string());
        }
        Command::Run => {
            let store = Store::open(&cli.data_dir.join(DB_FILE)).context("opening database")?;
            let node = Node::bind(config.clone(), identity.clone(), store)
                .await
                .with_context(|| format!("bind {}", config.listen))?;
            if config.public_host.is_none() && node.local_addr()?.ip().is_unspecified() {
                warn!("⚠️ public_host is not set — node address will contain 0.0.0.0; pass --public-host host:port");
            }
            print_info(&identity, &node.address().to_string());
            info!(
                "🚀 node started: listen={} bootstrap={} git_nodes={:?} name={:?} region={:?}",
                node.local_addr()?,
                config.bootstrap.len(),
                config.git_nodes,
                config.name,
                config.region
            );
            tokio::select! {
                res = node.run() => res?,
                _ = shutdown_signal() => info!("🛑 shutting down"),
            }
        }
    }
    Ok(())
}

fn prepare(cli: &Cli) -> anyhow::Result<(Config, NodeIdentity)> {
    std::fs::create_dir_all(&cli.data_dir).with_context(|| format!("creating {}", cli.data_dir.display()))?;
    let mut config = load_or_create_config(&cli.data_dir.join(CONFIG_FILE))?;
    if let Some(v) = &cli.listen {
        config.listen = v.clone();
    }
    if let Some(v) = &cli.public_host {
        config.public_host = Some(v.clone());
    }
    if let Some(v) = &cli.extra_addresses {
        config.extra_addresses = v.clone();
    }
    if let Some(v) = &cli.bootstrap {
        config.bootstrap = v.clone();
    }
    if let Some(v) = &cli.git_nodes {
        config.git_nodes = core_node::discovery::list_url(v);
    }
    if let Some(v) = &cli.name {
        config.name = v.clone();
    }
    if let Some(v) = &cli.region {
        config.region = v.clone();
    }

    let identity = match &cli.identity_seed {
        Some(seed) => {
            warn!("🧪 identity derived from seed — TESTNET ONLY, anyone who knows the seed owns this node");
            NodeIdentity::from_seed(seed)
        }
        None => {
            let path = cli.data_dir.join(IDENTITY_FILE);
            let (identity, created) = NodeIdentity::load_or_create(&path)?;
            if created {
                info!("🆔 new node identity created: {}", path.display());
            }
            identity
        }
    };
    Ok((config, identity))
}

fn load_or_create_config(path: &Path) -> anyhow::Result<Config> {
    if path.exists() {
        return Config::load(path).with_context(|| format!("reading {}", path.display()));
    }
    let config = Config::default();
    config.save(path)?;
    info!("📝 default config created: {}", path.display());
    Ok(config)
}

fn print_info(identity: &NodeIdentity, address: &str) {
    println!("node_id: {}", hex::encode(identity.node_id()));
    println!("address: {address}");
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}
