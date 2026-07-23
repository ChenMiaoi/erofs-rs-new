use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use erofs_lab::{
    IntegrityPolicy, MutationMode, ObjectRef,
    campaign::{
        CampaignBudget, CampaignSpec, CampaignTarget, FunnelPolicy, MinimizeRequest, minimize_case,
        run_campaign,
    },
    oracle::{OracleProfile, ResourceLimits},
};

use crate::oracle::{Profile, oracle_paths};

#[derive(Args, Debug)]
pub struct CampaignArgs {
    #[command(subcommand)]
    command: CampaignCommand,
}

#[derive(Subcommand, Debug)]
enum CampaignCommand {
    /// Generate deterministic cases, materialize samples, and optionally run the funnel.
    Run(RunArgs),
    /// Minimize one recipe case while preserving an oracle signature.
    Minimize(MinimizeArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Corrupt,
    Consistent,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Integrity {
    Preserve,
    Recalculate,
    Invalidate,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Funnel {
    Novelty,
    All,
    MaterializeOnly,
}
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ObjectKind {
    Superblock,
    Inode,
    Dirent,
}

#[derive(Args, Debug)]
struct RunArgs {
    image: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    seed: u64,
    #[arg(long, value_enum, default_value_t = Mode::Corrupt)]
    mode: Mode,
    #[arg(long, value_enum, default_value_t = Integrity::Preserve)]
    integrity: Integrity,
    #[arg(long, value_enum, default_value_t = Funnel::Novelty)]
    funnel: Funnel,
    /// Repeatable stable field ID. All targets share the object selector below.
    #[arg(long = "field", required = true)]
    fields: Vec<String>,
    #[arg(long, value_enum, default_value_t = ObjectKind::Superblock)]
    object: ObjectKind,
    #[arg(long, default_value = "primary", value_parser = ["primary"])]
    space: String,
    #[arg(long)]
    nid: Option<u64>,
    #[arg(long, default_value_t = 0)]
    block: u64,
    #[arg(long, default_value_t = 0)]
    index: u32,
    #[arg(long, default_value_t = 64)]
    max_samples: u64,
    #[arg(long, default_value_t = 4)]
    max_mutations: u64,
    #[arg(long, default_value_t = 1 << 30)]
    max_image_bytes: u64,
    #[arg(long, default_value_t = 64)]
    max_oracle_runs: u64,
    #[arg(long, default_value_t = 300_000)]
    wall_time_ms: u64,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

#[derive(Args, Debug)]
struct MinimizeArgs {
    image: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long)]
    recipe: PathBuf,
    #[arg(long)]
    case: String,
    #[arg(long, value_enum)]
    profile: Profile,
    #[arg(long)]
    signature: String,
    #[arg(long, default_value_t = 2)]
    confirmations: u32,
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
}

pub fn campaign(args: CampaignArgs) -> Result<()> {
    match args.command {
        CampaignCommand::Run(args) => run(args),
        CampaignCommand::Minimize(args) => minimize(args),
    }
}

fn run(args: RunArgs) -> Result<()> {
    let object = object(args.object, &args.space, args.nid, args.block, args.index)?;
    let spec = CampaignSpec {
        seed: args.seed.to_string(),
        mode: mode(args.mode),
        integrity: integrity(args.integrity),
        targets: args
            .fields
            .into_iter()
            .map(|field| CampaignTarget {
                object: object.clone(),
                field,
            })
            .collect(),
        budget: CampaignBudget {
            max_samples: args.max_samples,
            max_mutations_per_sample: args.max_mutations,
            max_image_bytes: args.max_image_bytes,
            max_oracle_runs: args.max_oracle_runs,
            wall_time_ms: args.wall_time_ms,
        },
        funnel: funnel(args.funnel),
    };
    let paths = if spec.funnel == FunnelPolicy::MaterializeOnly {
        None
    } else {
        Some(oracle_paths(&args.workspace)?)
    };
    let published = run_campaign(
        &args.image,
        &args.output_dir,
        spec,
        paths.as_ref(),
        ResourceLimits::default(),
    )?;
    println!("recipe: {}", published.recipe.display());
    println!("report: {}", published.report.display());
    println!("novelty: {}", published.novelty.display());
    println!("samples: {}", published.result.samples_materialized);
    println!("oracle-runs: {}", published.result.oracle_runs);
    println!("stopped: {}", published.result.stopped_reason);
    Ok(())
}

fn minimize(args: MinimizeArgs) -> Result<()> {
    let paths = oracle_paths(&args.workspace)?;
    let limits = ResourceLimits {
        timeout_ms: args.timeout_ms,
        ..ResourceLimits::default()
    };
    let output = minimize_case(MinimizeRequest {
        parent_path: &args.image,
        corpus: &args.output_dir,
        recipe_path: &args.recipe,
        case_id: &args.case,
        profile: OracleProfile::from(args.profile),
        target_signature: &args.signature,
        oracle_paths: &paths,
        limits,
        confirmations: args.confirmations,
    })?;
    println!("minimized: {}", output.display());
    Ok(())
}

fn object(
    kind: ObjectKind,
    space: &str,
    nid: Option<u64>,
    block: u64,
    index: u32,
) -> Result<ObjectRef> {
    match kind {
        ObjectKind::Superblock => Ok(ObjectRef::Superblock),
        ObjectKind::Inode => Ok(ObjectRef::Inode {
            space: space.into(),
            nid: nid.context("--nid is required for inode")?.to_string(),
        }),
        ObjectKind::Dirent => Ok(ObjectRef::Dirent {
            directory: nid.context("--nid is required for dirent")?.to_string(),
            block: block.to_string(),
            index,
        }),
    }
}
fn mode(value: Mode) -> MutationMode {
    match value {
        Mode::Corrupt => MutationMode::Corrupt,
        Mode::Consistent => MutationMode::Consistent,
    }
}
fn integrity(value: Integrity) -> IntegrityPolicy {
    match value {
        Integrity::Preserve => IntegrityPolicy::Preserve,
        Integrity::Recalculate => IntegrityPolicy::Recalculate,
        Integrity::Invalidate => IntegrityPolicy::Invalidate,
    }
}
fn funnel(value: Funnel) -> FunnelPolicy {
    match value {
        Funnel::Novelty => FunnelPolicy::Novelty,
        Funnel::All => FunnelPolicy::All,
        Funnel::MaterializeOnly => FunnelPolicy::MaterializeOnly,
    }
}
