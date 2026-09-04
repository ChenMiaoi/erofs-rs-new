use anyhow::Result;
use clap::{Parser, Subcommand};

mod campaign;
mod convert;
mod dashboard;
mod dump;
mod field;
mod inject;
mod inspect;
mod mkfs;
mod oracle;
mod replay;
mod view;

#[derive(Subcommand, Debug)]
enum Commands {
    Campaign(campaign::CampaignArgs),
    Dump(dump::DumpArgs),
    Field(field::FieldArgs),
    Inject(inject::InjectArgs),
    Inspect(inspect::InspectArgs),
    Mkfs(mkfs::MkfsArgs),
    Convert(convert::ConvertArgs),
    Oracle(oracle::OracleArgs),
    Replay(replay::ReplayArgs),
    View(view::ViewArgs),
}

#[derive(Debug, Parser)]
struct Opt {
    #[command(subcommand)]
    command: Commands,
}

/// Parses `s` as a remote image URL, returning the URL only for the http(s)
/// schemes; anything else (including local files named http*) is treated as a
/// local path.
fn remote_url(s: &str) -> Option<url::Url> {
    url::Url::parse(s)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    match opt.command {
        Commands::Campaign(args) => campaign::campaign(args),
        Commands::Dump(args) => dump::dump(args).await,
        Commands::Field(args) => field::field(args),
        Commands::Inject(args) => inject::inject(args),
        Commands::Inspect(args) => inspect::inspect(args).await,
        Commands::Mkfs(args) => mkfs::mkfs(args),
        Commands::Convert(args) => convert::convert(args),
        Commands::Oracle(args) => oracle::oracle(args),
        Commands::Replay(args) => replay::replay_sample(args),
        Commands::View(args) => view::view(args),
    }
}

#[cfg(test)]
mod tests {
    use super::remote_url;

    #[test]
    fn remote_url_accepts_http_and_https() {
        assert!(remote_url("http://example.com/image.erofs").is_some());
        assert!(remote_url("https://example.com/image.erofs").is_some());
    }

    #[test]
    fn remote_url_rejects_local_paths_and_bogus_schemes() {
        assert!(remote_url("httpdir/image.erofs").is_none());
        assert!(remote_url("/tmp/http.erofs").is_none());
        assert!(remote_url("ftp://example.com/image.erofs").is_none());
        assert!(remote_url("httpx://example.com/image.erofs").is_none());
    }
}
