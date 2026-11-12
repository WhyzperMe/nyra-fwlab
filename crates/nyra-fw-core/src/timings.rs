//! Opt-in wall-clock measurements kept separate from deterministic evidence.
use serde::Serialize;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

#[derive(Clone, Copy, Serialize)]
#[repr(usize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    InputRead,
    InputHash,
    ArchiveIndex,
    Recovery,
    Staging,
    Analysis,
    SquashFs,
    Ghidra,
    VerifyStage,
    Publish,
    VerifyReuse,
}

const PHASES: [Phase; 11] = [
    Phase::InputRead,
    Phase::InputHash,
    Phase::ArchiveIndex,
    Phase::Recovery,
    Phase::Staging,
    Phase::Analysis,
    Phase::SquashFs,
    Phase::Ghidra,
    Phase::VerifyStage,
    Phase::Publish,
    Phase::VerifyReuse,
];

#[derive(Debug, Default)]
pub struct RunTimings {
    samples: [Sample; PHASES.len()],
}

#[derive(Debug, Default)]
struct Sample {
    nanos: AtomicU64,
    calls: AtomicU64,
}

#[derive(Serialize)]
pub struct Measurement {
    phase: Phase,
    elapsed_ns: u64,
    calls: u64,
}

impl RunTimings {
    pub fn measure<T>(&self, phase: Phase, work: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = work();
        let sample = &self.samples[phase as usize];
        sample.nanos.fetch_add(
            start.elapsed().as_nanos().try_into().unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        sample.calls.fetch_add(1, Ordering::Relaxed);
        result
    }

    pub fn measurements(&self) -> Vec<Measurement> {
        PHASES
            .into_iter()
            .zip(&self.samples)
            .filter_map(|(phase, sample)| {
                let calls = sample.calls.load(Ordering::Relaxed);
                (calls != 0).then(|| Measurement {
                    phase,
                    elapsed_ns: sample.nanos.load(Ordering::Relaxed),
                    calls,
                })
            })
            .collect()
    }
}
