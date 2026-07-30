//! Deterministic campaigns, novelty tracking, execution funnels, and minimization.

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use erofs_format::schema::{Encoding, field_by_id};
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Error, IntegrityPolicy, MutationIntent, MutationMode, ObjectRef, PublishedSample,
    apply_resolved_plan, materialize,
    oracle::{OraclePaths, OracleProfile, OracleStatus, PublishedRun, ResourceLimits, run_oracle},
    plan,
};

const RECIPE_SCHEMA: &str = "erofs-mutation-recipe/v1";
const REPORT_SCHEMA: &str = "erofs-campaign-report/v1";
const NOVELTY_SCHEMA: &str = "erofs-novelty-index/v1";
const MINIMIZED_SCHEMA: &str = "erofs-minimized-recipe/v1";
const PRNG: &str = "chacha12/v1";

/// One symbolic field target available to a campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignTarget {
    pub object: ObjectRef,
    pub field: String,
}

/// Hard campaign budgets. Every execution path checks these values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignBudget {
    pub max_samples: u64,
    pub max_mutations_per_sample: u64,
    pub max_image_bytes: u64,
    pub max_oracle_runs: u64,
    pub wall_time_ms: u64,
}

/// Policy controlling escalation beyond the cheap Rust oracle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunnelPolicy {
    /// Escalate new signatures and disagreements; sample some cheap rejections.
    Novelty,
    /// Run all configured oracle levels until the oracle budget is exhausted.
    All,
    /// Materialize only; useful for deterministic corpus generation.
    MaterializeOnly,
}

/// Deterministic campaign input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignSpec {
    pub seed: String,
    pub mode: MutationMode,
    pub integrity: IntegrityPolicy,
    pub targets: Vec<CampaignTarget>,
    pub budget: CampaignBudget,
    pub funnel: FunnelPolicy,
}

/// Serializable mutation recipe intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecipeIntent {
    SetValue {
        object: ObjectRef,
        field: String,
        value: String,
    },
    UpdateBits {
        object: ObjectRef,
        field: String,
        set: String,
        clear: String,
    },
    ReplaceFixedBytes {
        object: ObjectRef,
        field: String,
        hex: String,
    },
    PatchBytes {
        offset: String,
        hex: String,
    },
    TruncateImage {
        new_len: String,
    },
}

impl RecipeIntent {
    fn resolve(&self) -> Result<MutationIntent, Error> {
        match self {
            Self::SetValue {
                object,
                field,
                value,
            } => Ok(MutationIntent::SetValue {
                object: object.clone(),
                field: field.clone(),
                value: parse_u64(value)?,
            }),
            Self::UpdateBits {
                object,
                field,
                set,
                clear,
            } => Ok(MutationIntent::UpdateBits {
                object: object.clone(),
                field: field.clone(),
                set: parse_u64(set)?,
                clear: parse_u64(clear)?,
            }),
            Self::ReplaceFixedBytes { object, field, hex } => {
                Ok(MutationIntent::ReplaceFixedBytes {
                    object: object.clone(),
                    field: field.clone(),
                    bytes: decode_hex(hex)?,
                })
            }
            Self::PatchBytes { offset, hex } => Ok(MutationIntent::PatchBytes {
                offset: parse_u64(offset)?,
                bytes: decode_hex(hex)?,
            }),
            Self::TruncateImage { new_len } => Ok(MutationIntent::TruncateImage {
                new_len: parse_u64(new_len)?,
            }),
        }
    }
}

/// One realized deterministic campaign case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeCase {
    pub id: String,
    pub generator: String,
    pub intents: Vec<RecipeIntent>,
}

/// Immutable recipe. `seed + spec` rebuilds cases; recorded cases remain audit authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRecipe {
    pub schema: String,
    pub prng: String,
    pub parent_sha256: String,
    pub parent_length: String,
    pub spec: CampaignSpec,
    pub cases: Vec<RecipeCase>,
}

/// Stable identity of one oracle result.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultIdentity {
    pub profile: String,
    pub status: String,
    pub phase: String,
    pub signature: String,
}

/// Persistent deduplication identities.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoveltyIndex {
    pub schema: String,
    pub byte_sha256: BTreeSet<String>,
    pub plan_sha256: BTreeSet<String>,
    pub results: BTreeSet<ResultIdentity>,
    pub coverage_sha256: BTreeSet<String>,
}

/// One materialized case and its escalated oracle results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignCaseReport {
    pub case_id: String,
    pub sample_sha256: Option<String>,
    pub plan_sha256: Option<String>,
    pub duplicate_bytes: bool,
    pub duplicate_plan: bool,
    pub planning_error: Option<String>,
    pub oracle_results: Vec<ResultIdentity>,
}

/// Campaign execution report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignReport {
    pub schema: String,
    pub recipe: String,
    pub cases: Vec<CampaignCaseReport>,
    pub samples_materialized: String,
    pub oracle_runs: String,
    pub stopped_reason: String,
}

/// Paths published by one campaign.
#[derive(Clone, Debug)]
pub struct PublishedCampaign {
    pub recipe: PathBuf,
    pub report: PathBuf,
    pub novelty: PathBuf,
    pub result: CampaignReport,
}

/// Incremental campaign state emitted after every completed case.
#[derive(Clone, Debug)]
pub struct CampaignProgress<'a> {
    pub total_cases: usize,
    pub completed_cases: usize,
    pub samples_materialized: u64,
    pub oracle_runs: u64,
    pub current_case: &'a CampaignCaseReport,
}

/// Result of signature-preserving minimization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizedRecipe {
    pub schema: String,
    pub source_recipe: String,
    pub source_case: String,
    pub profile: OracleProfile,
    pub target_signature: String,
    pub integrity: IntegrityPolicy,
    pub attempts: String,
    pub confirmations: String,
    pub intents: Vec<RecipeIntent>,
    pub sample_manifest: String,
}

/// Rebuilds deterministic cases from a parent identity and campaign spec.
pub fn generate_recipe(parent: &[u8], spec: CampaignSpec) -> Result<CampaignRecipe, Error> {
    if parent.len() as u64 > spec.budget.max_image_bytes {
        return Err(Error::Bounds);
    }
    if spec.targets.is_empty() || spec.budget.max_samples == 0 {
        return Err(Error::Unsupported(
            "campaign requires targets and sample budget",
        ));
    }
    let seed = parse_u64(&spec.seed)?;
    let mut cases = deterministic_cases(&spec.targets)?;
    let remaining = usize::try_from(spec.budget.max_samples)
        .map_err(|_| Error::Bounds)?
        .saturating_sub(cases.len());
    cases.extend(combination_cases(
        &spec.targets,
        seed,
        remaining,
        spec.budget.max_mutations_per_sample,
    )?);
    cases.truncate(usize::try_from(spec.budget.max_samples).map_err(|_| Error::Bounds)?);
    Ok(CampaignRecipe {
        schema: RECIPE_SCHEMA.into(),
        prng: PRNG.into(),
        parent_sha256: sha256(parent),
        parent_length: parent.len().to_string(),
        spec,
        cases,
    })
}

/// Verifies that a recorded recipe is exactly regenerated by its seed and spec.
pub fn verify_recipe(parent: &[u8], recipe: &CampaignRecipe) -> Result<(), Error> {
    if recipe.schema != RECIPE_SCHEMA || recipe.prng != PRNG {
        return Err(Error::Unsupported("campaign recipe schema"));
    }
    if recipe.parent_sha256 != sha256(parent) || recipe.parent_length != parent.len().to_string() {
        return Err(Error::ParentIdentity);
    }
    let rebuilt = generate_recipe(parent, recipe.spec.clone())?;
    if rebuilt.cases != recipe.cases {
        return Err(Error::OutputIdentity);
    }
    Ok(())
}

/// Materializes recipe cases, applies the oracle funnel, and updates novelty identities.
pub fn run_campaign(
    parent_path: &Path,
    corpus: &Path,
    spec: CampaignSpec,
    oracle_paths: Option<&OraclePaths>,
    limits: ResourceLimits,
) -> Result<PublishedCampaign, Error> {
    run_campaign_with_progress(parent_path, corpus, spec, oracle_paths, limits, |_| {})
}

/// Runs a campaign and reports completed-case statistics synchronously.
pub fn run_campaign_with_progress<F>(
    parent_path: &Path,
    corpus: &Path,
    spec: CampaignSpec,
    oracle_paths: Option<&OraclePaths>,
    limits: ResourceLimits,
    mut progress: F,
) -> Result<PublishedCampaign, Error>
where
    F: FnMut(CampaignProgress<'_>),
{
    let parent = fs::read(parent_path)?;
    let recipe = generate_recipe(&parent, spec)?;
    let campaign_id = sha256(&serde_json::to_vec(&recipe)?);
    let campaign_dir = corpus.join("campaigns").join(&campaign_id);
    fs::create_dir_all(&campaign_dir)?;
    let recipe_path = campaign_dir.join("recipe.json");
    write_json_once(&recipe_path, &recipe)?;
    let novelty_path = corpus.join("novelty.json");
    let mut novelty = load_novelty(&novelty_path)?;
    let start = Instant::now();
    let mut oracle_runs = 0_u64;
    let mut materialized = 0_u64;
    let mut reports = Vec::new();
    let mut stopped_reason = "completed".to_string();
    let total_cases = recipe.cases.len();

    for case in &recipe.cases {
        if start.elapsed() > Duration::from_millis(recipe.spec.budget.wall_time_ms) {
            stopped_reason = "wall_time".into();
            break;
        }
        let intents = resolve_intents(&case.intents)?;
        let resolved = match plan(&parent, &intents, recipe.spec.mode, recipe.spec.integrity) {
            Ok(plan) => plan,
            Err(error) => {
                reports.push(CampaignCaseReport {
                    case_id: case.id.clone(),
                    sample_sha256: None,
                    plan_sha256: None,
                    duplicate_bytes: false,
                    duplicate_plan: false,
                    planning_error: Some(error.to_string()),
                    oracle_results: Vec::new(),
                });
                let current_case = reports.last().expect("report was just added");
                progress(CampaignProgress {
                    total_cases,
                    completed_cases: reports.len(),
                    samples_materialized: materialized,
                    oracle_runs,
                    current_case,
                });
                continue;
            }
        };
        let duplicate_plan = !novelty.plan_sha256.insert(resolved.plan_sha256.clone());
        let output_sha256 = sha256(&apply_resolved_plan(&parent, &resolved)?);
        let duplicate_bytes = !novelty.byte_sha256.insert(output_sha256.clone());
        if duplicate_bytes {
            reports.push(CampaignCaseReport {
                case_id: case.id.clone(),
                sample_sha256: Some(output_sha256),
                plan_sha256: Some(resolved.plan_sha256),
                duplicate_bytes,
                duplicate_plan,
                planning_error: None,
                oracle_results: Vec::new(),
            });
            let current_case = reports.last().expect("report was just added");
            progress(CampaignProgress {
                total_cases,
                completed_cases: reports.len(),
                samples_materialized: materialized,
                oracle_runs,
                current_case,
            });
            continue;
        }
        let sample = materialize(parent_path, corpus, &resolved)?;
        materialized += 1;
        let mut identities = Vec::new();
        if recipe.spec.funnel != FunnelPolicy::MaterializeOnly {
            let paths =
                oracle_paths.ok_or(Error::Unsupported("oracle paths required by funnel"))?;
            let rust = run_profile(&sample, OracleProfile::RustFull, paths, limits.clone())?;
            oracle_runs += 1;
            let rust_novel = record_result(&mut novelty, &rust, &mut identities);
            let must_escalate = recipe.spec.funnel == FunnelPolicy::All
                || rust_novel
                || matches!(
                    rust.result.status,
                    OracleStatus::Crashed
                        | OracleStatus::TimedOut
                        | OracleStatus::ResourceExhausted
                )
                || (rust.result.status == OracleStatus::Rejected && seeded_retention(&case.id));
            if must_escalate && oracle_runs < recipe.spec.budget.max_oracle_runs {
                let fsck = run_profile(&sample, OracleProfile::FsckFull, paths, limits.clone())?;
                oracle_runs += 1;
                let fsck_novel = record_result(&mut novelty, &fsck, &mut identities);
                let disagreement = rust.result.status != fsck.result.status;
                if (recipe.spec.funnel == FunnelPolicy::All
                    || fsck_novel
                    || disagreement
                    || matches!(
                        fsck.result.status,
                        OracleStatus::Crashed
                            | OracleStatus::TimedOut
                            | OracleStatus::ResourceExhausted
                    ))
                    && oracle_runs < recipe.spec.budget.max_oracle_runs
                {
                    let linux =
                        run_profile(&sample, OracleProfile::LinuxKasan, paths, limits.clone())?;
                    oracle_runs += 1;
                    record_result(&mut novelty, &linux, &mut identities);
                }
            }
        }
        reports.push(CampaignCaseReport {
            case_id: case.id.clone(),
            sample_sha256: Some(sample.output_sha256),
            plan_sha256: Some(resolved.plan_sha256),
            duplicate_bytes,
            duplicate_plan,
            planning_error: None,
            oracle_results: identities,
        });
        let current_case = reports.last().expect("report was just added");
        progress(CampaignProgress {
            total_cases,
            completed_cases: reports.len(),
            samples_materialized: materialized,
            oracle_runs,
            current_case,
        });
        if oracle_runs >= recipe.spec.budget.max_oracle_runs
            && recipe.spec.funnel != FunnelPolicy::MaterializeOnly
        {
            stopped_reason = "oracle_budget".into();
            break;
        }
    }
    save_novelty(&novelty_path, &novelty)?;
    let report = CampaignReport {
        schema: REPORT_SCHEMA.into(),
        recipe: recipe_path.display().to_string(),
        cases: reports,
        samples_materialized: materialized.to_string(),
        oracle_runs: oracle_runs.to_string(),
        stopped_reason,
    };
    let report_path = campaign_dir.join("report.json");
    write_json_replace(&report_path, &report)?;
    Ok(PublishedCampaign {
        recipe: recipe_path,
        report: report_path,
        novelty: novelty_path,
        result: report,
    })
}

/// Inputs for one signature-preserving minimization run.
pub struct MinimizeRequest<'a> {
    pub parent_path: &'a Path,
    pub corpus: &'a Path,
    pub recipe_path: &'a Path,
    pub case_id: &'a str,
    pub profile: OracleProfile,
    pub target_signature: &'a str,
    pub oracle_paths: &'a OraclePaths,
    pub limits: ResourceLimits,
    pub confirmations: u32,
}

/// Delta-debugs one recipe case while preserving profile signature and integrity policy.
pub fn minimize_case(request: MinimizeRequest<'_>) -> Result<PathBuf, Error> {
    let MinimizeRequest {
        parent_path,
        corpus,
        recipe_path,
        case_id,
        profile,
        target_signature,
        oracle_paths,
        limits,
        confirmations,
    } = request;
    let parent = fs::read(parent_path)?;
    let recipe: CampaignRecipe = serde_json::from_slice(&fs::read(recipe_path)?)?;
    verify_recipe(&parent, &recipe)?;
    let case = recipe
        .cases
        .iter()
        .find(|case| case.id == case_id)
        .ok_or(Error::Unsupported("campaign case not found"))?;
    let mut current = case.intents.clone();
    let mut attempts = 0_u64;
    let confirms = confirmations.max(2);
    if !preserves_signature(
        parent_path,
        corpus,
        &parent,
        &current,
        recipe.spec.mode,
        recipe.spec.integrity,
        profile,
        target_signature,
        oracle_paths,
        limits.clone(),
        confirms,
        &mut attempts,
    )? {
        return Err(Error::Unsupported(
            "source case does not preserve target signature",
        ));
    }

    let mut index = 0;
    while index < current.len() {
        let mut candidate = current.clone();
        candidate.remove(index);
        if !candidate.is_empty()
            && preserves_signature(
                parent_path,
                corpus,
                &parent,
                &candidate,
                recipe.spec.mode,
                recipe.spec.integrity,
                profile,
                target_signature,
                oracle_paths,
                limits.clone(),
                confirms,
                &mut attempts,
            )?
        {
            current = candidate;
        } else {
            index += 1;
        }
    }
    for index in 0..current.len() {
        for candidate_intent in shrink_intent(&current[index], parent.len() as u64)? {
            let mut candidate = current.clone();
            candidate[index] = candidate_intent;
            if preserves_signature(
                parent_path,
                corpus,
                &parent,
                &candidate,
                recipe.spec.mode,
                recipe.spec.integrity,
                profile,
                target_signature,
                oracle_paths,
                limits.clone(),
                confirms,
                &mut attempts,
            )? {
                current = candidate;
            }
        }
    }
    let intents = resolve_intents(&current)?;
    let resolved = plan(&parent, &intents, recipe.spec.mode, recipe.spec.integrity)?;
    let sample = materialize(parent_path, corpus, &resolved)?;
    let output = MinimizedRecipe {
        schema: MINIMIZED_SCHEMA.into(),
        source_recipe: recipe_path.display().to_string(),
        source_case: case_id.into(),
        profile,
        target_signature: target_signature.into(),
        integrity: recipe.spec.integrity,
        attempts: attempts.to_string(),
        confirmations: confirms.to_string(),
        intents: current,
        sample_manifest: sample.manifest.display().to_string(),
    };
    let minimized_dir = corpus.join("minimized");
    fs::create_dir_all(&minimized_dir)?;
    let path = minimized_dir.join(format!("{}-{}.json", case_id, sample.output_sha256));
    write_json_replace(&path, &output)?;
    Ok(path)
}

fn deterministic_cases(targets: &[CampaignTarget]) -> Result<Vec<RecipeCase>, Error> {
    let mut cases = Vec::new();
    for target in targets {
        let field = field_by_id(&target.field)
            .ok_or_else(|| Error::Resolve(format!("unknown field {}", target.field)))?;
        if field.encoding == Encoding::Bytes {
            continue;
        }
        let max = width_max(field.storage.len)?;
        let mut values = vec![0, max, 1];
        if max > 0 {
            values.push(max - 1);
        }
        values.sort_unstable();
        values.dedup();
        for value in values {
            let intents = vec![RecipeIntent::SetValue {
                object: target.object.clone(),
                field: target.field.clone(),
                value: value.to_string(),
            }];
            cases.push(case("enumerate-value", &intents)?);
        }
        for bit in 0..field.storage.len * 8 {
            let intents = vec![RecipeIntent::UpdateBits {
                object: target.object.clone(),
                field: target.field.clone(),
                set: (1_u64 << bit).to_string(),
                clear: "0".into(),
            }];
            cases.push(case("enumerate-bit", &intents)?);
        }
    }
    Ok(cases)
}

fn combination_cases(
    targets: &[CampaignTarget],
    seed: u64,
    count: usize,
    max_mutations: u64,
) -> Result<Vec<RecipeCase>, Error> {
    let mut seed_bytes = [0; 32];
    seed_bytes[..8].copy_from_slice(&seed.to_le_bytes());
    seed_bytes[8..16].copy_from_slice(&(!seed).to_le_bytes());
    let mut rng = ChaCha12Rng::from_seed(seed_bytes);
    let max = usize::try_from(max_mutations)
        .map_err(|_| Error::Bounds)?
        .min(targets.len());
    if max == 0 {
        return Ok(Vec::new());
    }
    let mut cases = Vec::new();
    for _ in 0..count {
        let mutations = 1 + (rng.next_u64() as usize % max);
        let mut selected = BTreeSet::new();
        while selected.len() < mutations {
            selected.insert(rng.next_u64() as usize % targets.len());
        }
        let mut intents = Vec::new();
        for index in selected {
            let target = &targets[index];
            let field = field_by_id(&target.field)
                .ok_or_else(|| Error::Resolve(format!("unknown field {}", target.field)))?;
            if field.encoding == Encoding::Bytes {
                continue;
            }
            let value = rng.next_u64() & width_max(field.storage.len)?;
            intents.push(RecipeIntent::SetValue {
                object: target.object.clone(),
                field: target.field.clone(),
                value: value.to_string(),
            });
        }
        if !intents.is_empty() {
            cases.push(case("dependency-combination", &intents)?);
        }
    }
    Ok(cases)
}

fn case(generator: &str, intents: &[RecipeIntent]) -> Result<RecipeCase, Error> {
    let id = sha256(&serde_json::to_vec(intents)?);
    Ok(RecipeCase {
        id,
        generator: generator.into(),
        intents: intents.to_vec(),
    })
}

fn run_profile(
    sample: &PublishedSample,
    profile: OracleProfile,
    paths: &OraclePaths,
    mut limits: ResourceLimits,
) -> Result<PublishedRun, Error> {
    if profile == OracleProfile::LinuxKasan {
        limits.timeout_ms = limits.timeout_ms.max(80_000);
        limits.cpu_seconds = limits.cpu_seconds.max(80);
        limits.address_space_bytes = limits.address_space_bytes.max(3 << 30);
        limits.processes = limits.processes.max(64);
        limits.output_bytes = limits.output_bytes.max(8 << 20);
    }
    run_oracle(&sample.manifest, profile, paths, limits)
}

fn record_result(
    novelty: &mut NoveltyIndex,
    run: &PublishedRun,
    output: &mut Vec<ResultIdentity>,
) -> bool {
    let identity = result_identity(run);
    let novel = novelty.results.insert(identity.clone());
    output.push(identity);
    novel
}

fn result_identity(run: &PublishedRun) -> ResultIdentity {
    ResultIdentity {
        profile: run
            .result
            .signature
            .split(':')
            .next()
            .unwrap_or("oracle")
            .into(),
        status: status_name(run.result.status).into(),
        phase: phase_name(run.result.phase).into(),
        signature: run.result.signature.clone(),
    }
}

fn status_name(status: OracleStatus) -> &'static str {
    match status {
        OracleStatus::Accepted => "accepted",
        OracleStatus::Rejected => "rejected",
        OracleStatus::Crashed => "crashed",
        OracleStatus::TimedOut => "timed_out",
        OracleStatus::ResourceExhausted => "resource_exhausted",
        OracleStatus::Unsupported => "unsupported",
        OracleStatus::HarnessError => "harness_error",
    }
}

fn phase_name(phase: crate::oracle::OraclePhase) -> &'static str {
    match phase {
        crate::oracle::OraclePhase::Open => "open",
        crate::oracle::OraclePhase::Superblock => "superblock",
        crate::oracle::OraclePhase::Mount => "mount",
        crate::oracle::OraclePhase::Inode => "inode",
        crate::oracle::OraclePhase::Lookup => "lookup",
        crate::oracle::OraclePhase::Readdir => "readdir",
        crate::oracle::OraclePhase::Traverse => "traverse",
        crate::oracle::OraclePhase::ReadData => "read_data",
        crate::oracle::OraclePhase::MapData => "map_data",
        crate::oracle::OraclePhase::Decompress => "decompress",
        crate::oracle::OraclePhase::Xattr => "xattr",
        crate::oracle::OraclePhase::Unmount => "unmount",
        crate::oracle::OraclePhase::Unknown => "unknown",
    }
}
fn seeded_retention(case_id: &str) -> bool {
    case_id.as_bytes().first().is_some_and(|byte| byte % 8 == 0)
}
fn resolve_intents(intents: &[RecipeIntent]) -> Result<Vec<MutationIntent>, Error> {
    intents.iter().map(RecipeIntent::resolve).collect()
}

#[allow(clippy::too_many_arguments)]
fn preserves_signature(
    parent_path: &Path,
    corpus: &Path,
    parent: &[u8],
    intents: &[RecipeIntent],
    mode: MutationMode,
    integrity: IntegrityPolicy,
    profile: OracleProfile,
    signature: &str,
    paths: &OraclePaths,
    limits: ResourceLimits,
    confirmations: u32,
    attempts: &mut u64,
) -> Result<bool, Error> {
    let resolved = match plan(parent, &resolve_intents(intents)?, mode, integrity) {
        Ok(plan) => plan,
        Err(_) => return Ok(false),
    };
    let sample = materialize(parent_path, corpus, &resolved)?;
    for _ in 0..confirmations {
        *attempts += 1;
        let run = run_profile(&sample, profile, paths, limits.clone())?;
        if run.result.signature != signature {
            return Ok(false);
        }
    }
    Ok(true)
}

fn shrink_intent(intent: &RecipeIntent, parent_len: u64) -> Result<Vec<RecipeIntent>, Error> {
    let mut output = Vec::new();
    match intent {
        RecipeIntent::SetValue {
            object,
            field,
            value,
        } => {
            let value = parse_u64(value)?;
            for smaller in [0, 1, value / 2] {
                if smaller < value {
                    output.push(RecipeIntent::SetValue {
                        object: object.clone(),
                        field: field.clone(),
                        value: smaller.to_string(),
                    });
                }
            }
        }
        RecipeIntent::UpdateBits {
            object,
            field,
            set,
            clear,
        } => {
            let set = parse_u64(set)?;
            let clear = parse_u64(clear)?;
            if set.count_ones() > 1 {
                output.push(RecipeIntent::UpdateBits {
                    object: object.clone(),
                    field: field.clone(),
                    set: (set & set.wrapping_neg()).to_string(),
                    clear: clear.to_string(),
                });
            }
            if clear.count_ones() > 1 {
                output.push(RecipeIntent::UpdateBits {
                    object: object.clone(),
                    field: field.clone(),
                    set: set.to_string(),
                    clear: (clear & clear.wrapping_neg()).to_string(),
                });
            }
        }
        RecipeIntent::PatchBytes { offset, hex } => {
            let bytes = decode_hex(hex)?;
            if bytes.len() > 1 {
                output.push(RecipeIntent::PatchBytes {
                    offset: offset.clone(),
                    hex: encode_hex(&bytes[..bytes.len() / 2]),
                });
            }
        }
        RecipeIntent::ReplaceFixedBytes { .. } => {}
        RecipeIntent::TruncateImage { new_len } => {
            let length = parse_u64(new_len)?;
            let delta = parent_len.saturating_sub(length);
            if delta > 1 {
                output.push(RecipeIntent::TruncateImage {
                    new_len: (parent_len - delta / 2).to_string(),
                });
            }
        }
    }
    Ok(output)
}

fn load_novelty(path: &Path) -> Result<NoveltyIndex, Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(NoveltyIndex {
            schema: NOVELTY_SCHEMA.into(),
            ..NoveltyIndex::default()
        }),
        Err(error) => Err(error.into()),
    }
}
fn save_novelty(path: &Path, novelty: &NoveltyIndex) -> Result<(), Error> {
    write_json_replace(path, novelty)
}
fn write_json_once<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let bytes = serde_json::to_vec(value)?;
    match fs::write(path, &bytes) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn write_json_replace<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let temporary = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}
fn width_max(len: u64) -> Result<u64, Error> {
    if len == 8 {
        Ok(u64::MAX)
    } else {
        1_u64
            .checked_shl((len * 8) as u32)
            .map(|value| value - 1)
            .ok_or(Error::Bounds)
    }
}
fn parse_u64(value: &str) -> Result<u64, Error> {
    value
        .parse()
        .map_err(|_| Error::InvalidInteger(value.into()))
}
fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn encode_hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(H[(byte >> 4) as usize] as char);
        result.push(H[(byte & 15) as usize] as char);
    }
    result
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).ok_or(Error::InvalidHex)?;
            let low = (pair[1] as char).to_digit(16).ok_or(Error::InvalidHex)?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image() -> Vec<u8> {
        let mut image = vec![0; 4096];
        image[1024..1028].copy_from_slice(&erofs_format::SUPERBLOCK_MAGIC.to_le_bytes());
        image[1036] = 12;
        image
    }
    fn spec(seed: u64) -> CampaignSpec {
        CampaignSpec {
            seed: seed.to_string(),
            mode: MutationMode::Corrupt,
            integrity: IntegrityPolicy::Preserve,
            targets: vec![CampaignTarget {
                object: ObjectRef::Superblock,
                field: "erofs.superblock.fixed_nsec".into(),
            }],
            budget: CampaignBudget {
                max_samples: 10,
                max_mutations_per_sample: 2,
                max_image_bytes: 4096,
                max_oracle_runs: 0,
                wall_time_ms: 1000,
            },
            funnel: FunnelPolicy::MaterializeOnly,
        }
    }
    #[test]
    fn seed_rebuilds_identical_intents() {
        let parent = image();
        let first = generate_recipe(&parent, spec(7)).unwrap();
        let second = generate_recipe(&parent, spec(7)).unwrap();
        assert_eq!(first.cases, second.cases);
        verify_recipe(&parent, &first).unwrap();
    }
    #[test]
    fn different_seeds_change_combination_tail() {
        let parent = image();
        let mut a = spec(1);
        a.targets.push(CampaignTarget {
            object: ObjectRef::Superblock,
            field: "erofs.superblock.epoch".into(),
        });
        a.budget.max_samples = 120;
        let mut b = a.clone();
        b.seed = "2".into();
        assert_ne!(
            generate_recipe(&parent, a).unwrap().cases,
            generate_recipe(&parent, b).unwrap().cases
        );
    }
    #[test]
    fn novelty_tracks_distinct_identity_classes() {
        let mut novelty = NoveltyIndex {
            schema: NOVELTY_SCHEMA.into(),
            ..NoveltyIndex::default()
        };
        assert!(novelty.byte_sha256.insert("a".into()));
        assert!(!novelty.byte_sha256.insert("a".into()));
        assert!(novelty.plan_sha256.insert("a".into()));
    }
    #[test]
    fn shrinking_values_and_raw_patches_is_monotonic() {
        let set = RecipeIntent::SetValue {
            object: ObjectRef::Superblock,
            field: "x".into(),
            value: "16".into(),
        };
        assert!(shrink_intent(&set, 100).unwrap().iter().all(|intent| matches!(intent, RecipeIntent::SetValue { value, .. } if parse_u64(value).unwrap() < 16)));
        let raw = RecipeIntent::PatchBytes {
            offset: "0".into(),
            hex: "00112233".into(),
        };
        assert_eq!(
            shrink_intent(&raw, 100).unwrap(),
            vec![RecipeIntent::PatchBytes {
                offset: "0".into(),
                hex: "0011".into()
            }]
        );
    }

    #[test]
    fn deterministic_enumeration_contains_boundaries_and_single_bits() {
        let parent = image();
        let mut specification = spec(9);
        specification.budget.max_samples = 40;
        let recipe = generate_recipe(&parent, specification).unwrap();
        assert!(recipe.cases.iter().any(|case| matches!(case.intents.as_slice(), [RecipeIntent::SetValue { value, .. }] if value == "0")));
        assert!(recipe.cases.iter().any(|case| matches!(case.intents.as_slice(), [RecipeIntent::SetValue { value, .. }] if value == "4294967295")));
        assert!(recipe.cases.iter().any(|case| matches!(case.intents.as_slice(), [RecipeIntent::UpdateBits { set, .. }] if set == "1")));
    }

    #[test]
    fn applying_recipe_case_rebuilds_identical_plan_and_bytes() {
        let parent = image();
        let recipe = generate_recipe(&parent, spec(11)).unwrap();
        let intents = resolve_intents(&recipe.cases[1].intents).unwrap();
        let first = plan(&parent, &intents, recipe.spec.mode, recipe.spec.integrity).unwrap();
        let second = plan(&parent, &intents, recipe.spec.mode, recipe.spec.integrity).unwrap();
        assert_eq!(first.plan_sha256, second.plan_sha256);
        assert_eq!(
            apply_resolved_plan(&parent, &first).unwrap(),
            apply_resolved_plan(&parent, &second).unwrap()
        );
    }

    #[test]
    fn duplicate_outputs_are_distinct_from_duplicate_plans() {
        let mut novelty = NoveltyIndex {
            schema: NOVELTY_SCHEMA.into(),
            ..NoveltyIndex::default()
        };
        assert!(novelty.byte_sha256.insert("bytes".into()));
        assert!(novelty.plan_sha256.insert("plan-a".into()));
        assert!(!novelty.byte_sha256.insert("bytes".into()));
        assert!(novelty.plan_sha256.insert("plan-b".into()));
    }
}
