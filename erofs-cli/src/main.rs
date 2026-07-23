use anyhow::Result;
use clap::{Parser, Subcommand};

mod convert;
mod dump;
mod field;
mod inject;
mod inspect;
mod replay;

#[derive(Subcommand, Debug)]
enum Commands {
    Dump(dump::DumpArgs),
    Field(field::FieldArgs),
    Inject(inject::InjectArgs),
    Inspect(inspect::InspectArgs),
    Convert(convert::ConvertArgs),
    Replay(replay::ReplayArgs),
}

#[derive(Debug, Parser)]
struct Opt {
    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    match opt.command {
        Commands::Dump(args) => dump::dump(args).await,
        Commands::Field(args) => field::field(args),
        Commands::Inject(args) => inject::inject(args),
        Commands::Inspect(args) => inspect::inspect(args).await,
        Commands::Convert(args) => convert::convert(args),
        Commands::Replay(args) => replay::replay_sample(args),
    }
}
