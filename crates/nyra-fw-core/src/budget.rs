//! Cooperative deadline and weighted admission of temporary work.
use crate::{
    FwError, Limits, Result,
    timings::{Phase, RunTimings},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct RunBudget {
    pub limits: Limits,
    deadline: Option<Instant>,
    active_bytes: u64,
    timings: Option<Arc<RunTimings>>,
}

impl RunBudget {
    pub fn new(limits: Limits, deadline: Option<Instant>) -> Self {
        Self {
            limits,
            deadline,
            active_bytes: 128 * 1024 * 1024,
            timings: None,
        }
    }

    pub fn with_timings(mut self, timings: Option<Arc<RunTimings>>) -> Self {
        self.timings = timings;
        self
    }

    pub fn measure<T>(&self, phase: Phase, work: impl FnOnce() -> T) -> T {
        match &self.timings {
            Some(timings) => timings.measure(phase, work),
            None => work(),
        }
    }

    pub fn checkpoint(&self) -> Result<()> {
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(FwError::Limit("run deadline exceeded".into()));
        }
        Ok(())
    }

    pub fn time_for(&self, requested: Duration) -> Result<Duration> {
        self.checkpoint()?;
        Ok(self.deadline.map_or(requested, |deadline| {
            requested.min(deadline.saturating_duration_since(Instant::now()))
        }))
    }

    /// Finish each batch before starting the next. Rayon workers never wait for
    /// a permit while holding work or memory needed by another worker.
    pub fn batches<T>(
        &self,
        mut jobs: &[T],
        weight: impl Fn(&T) -> u64,
        mut run: impl FnMut(&[T]) -> Result<()>,
    ) -> Result<()> {
        while !jobs.is_empty() {
            self.checkpoint()?;
            let mut available = self.active_bytes;
            let count = jobs
                .iter()
                .take(256)
                .take_while(|job| {
                    let bytes = weight(job);
                    if bytes > available {
                        return false;
                    }
                    available -= bytes;
                    true
                })
                .count();
            if count == 0 {
                return Err(FwError::Limit(
                    "job exceeds active decoder memory budget".into(),
                ));
            }
            let (batch, rest) = jobs.split_at(count);
            run(batch)?;
            jobs = rest;
        }
        self.checkpoint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_weighted_batches_in_order_and_rejects_oversized_work() {
        let budget = RunBudget {
            limits: Limits::default(),
            deadline: None,
            active_bytes: 10,
            timings: None,
        };
        let mut result = Vec::new();
        budget
            .batches(
                &[5, 4, 8, 1, 2],
                |&n| n,
                |batch| {
                    result.push(batch.to_vec());
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(result, [vec![5, 4], vec![8, 1], vec![2]]);
        assert!(
            budget
                .batches(&[11], |&n| n, |_| panic!("oversized batch"))
                .is_err()
        );
    }
}
