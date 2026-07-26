use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::{hash_domain, Hash32};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRevealRound {
    pub epoch_number: u64,
    validators: BTreeSet<Hash32>,
    commitments: BTreeMap<Hash32, Hash32>,
    reveals: BTreeMap<Hash32, Hash32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomnessOutcome {
    pub randomness: Hash32,
    pub missing_reveals: Vec<Hash32>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitRevealError {
    #[error("validator is not a member of this randomness round")]
    UnknownValidator,
    #[error("validator already submitted a commitment")]
    DuplicateCommitment,
    #[error("validator must commit before revealing")]
    MissingCommitment,
    #[error("validator already revealed")]
    DuplicateReveal,
    #[error("reveal does not match the validator commitment")]
    InvalidReveal,
    #[error("cannot finalize until all validators have committed")]
    IncompleteCommitments,
    #[error("only {actual} valid reveals are available; {required} required")]
    InsufficientReveals { actual: usize, required: usize },
    #[error("randomness round must contain at least one validator")]
    EmptyValidatorSet,
}

#[must_use]
pub fn commitment_for(epoch_number: u64, validator_id: &Hash32, secret_reveal: &Hash32) -> Hash32 {
    hash_domain(
        b"EPDN_RANDOM_COMMIT_V1",
        &[&epoch_number.to_be_bytes(), validator_id, secret_reveal],
    )
}

impl CommitRevealRound {
    pub fn new(
        epoch_number: u64,
        validators: impl IntoIterator<Item = Hash32>,
    ) -> Result<Self, CommitRevealError> {
        let validators: BTreeSet<_> = validators.into_iter().collect();
        if validators.is_empty() {
            return Err(CommitRevealError::EmptyValidatorSet);
        }
        Ok(Self {
            epoch_number,
            validators,
            commitments: BTreeMap::new(),
            reveals: BTreeMap::new(),
        })
    }

    pub fn commit(
        &mut self,
        validator_id: Hash32,
        commitment: Hash32,
    ) -> Result<(), CommitRevealError> {
        if !self.validators.contains(&validator_id) {
            return Err(CommitRevealError::UnknownValidator);
        }
        if self.commitments.contains_key(&validator_id) {
            return Err(CommitRevealError::DuplicateCommitment);
        }
        self.commitments.insert(validator_id, commitment);
        Ok(())
    }

    pub fn reveal(
        &mut self,
        validator_id: Hash32,
        secret_reveal: Hash32,
    ) -> Result<(), CommitRevealError> {
        if !self.validators.contains(&validator_id) {
            return Err(CommitRevealError::UnknownValidator);
        }
        let commitment = self
            .commitments
            .get(&validator_id)
            .ok_or(CommitRevealError::MissingCommitment)?;
        if self.reveals.contains_key(&validator_id) {
            return Err(CommitRevealError::DuplicateReveal);
        }
        if commitment_for(self.epoch_number, &validator_id, &secret_reveal) != *commitment {
            return Err(CommitRevealError::InvalidReveal);
        }
        self.reveals.insert(validator_id, secret_reveal);
        Ok(())
    }

    /// Finalizes a round in validator-ID order.
    ///
    /// A committed validator that withholds its reveal contributes its fixed
    /// commitment instead, with a distinct marker. The validator is also
    /// returned in `missing_reveals` so the caller can apply its penalty policy.
    pub fn finalize(&self, minimum_reveals: usize) -> Result<RandomnessOutcome, CommitRevealError> {
        if self.commitments.len() != self.validators.len() {
            return Err(CommitRevealError::IncompleteCommitments);
        }
        if self.reveals.len() < minimum_reveals {
            return Err(CommitRevealError::InsufficientReveals {
                actual: self.reveals.len(),
                required: minimum_reveals,
            });
        }

        let mut transcript = Vec::with_capacity(16 + self.validators.len().saturating_mul(65));
        transcript.extend_from_slice(&self.epoch_number.to_be_bytes());
        transcript.extend_from_slice(&(self.validators.len() as u64).to_be_bytes());
        let mut missing_reveals = Vec::new();
        for validator_id in &self.validators {
            transcript.extend_from_slice(validator_id);
            if let Some(reveal) = self.reveals.get(validator_id) {
                transcript.push(1);
                transcript.extend_from_slice(reveal);
            } else {
                transcript.push(0);
                if let Some(commitment) = self.commitments.get(validator_id) {
                    transcript.extend_from_slice(commitment);
                }
                missing_reveals.push(*validator_id);
            }
        }
        Ok(RandomnessOutcome {
            randomness: hash_domain(b"EPDN_RANDOMNESS_V1", &[&transcript]),
            missing_reveals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_validators_finalize_identically_in_any_arrival_order() {
        let validators = [[1; 32], [2; 32], [3; 32]];
        let reveals = [[11; 32], [12; 32], [13; 32]];
        let mut first = CommitRevealRound::new(77, validators).expect("round");
        let mut second = CommitRevealRound::new(77, validators.into_iter().rev()).expect("round");

        for index in [0, 1, 2] {
            first
                .commit(
                    validators[index],
                    commitment_for(77, &validators[index], &reveals[index]),
                )
                .expect("commit");
        }
        for index in [2, 0, 1] {
            second
                .commit(
                    validators[index],
                    commitment_for(77, &validators[index], &reveals[index]),
                )
                .expect("commit");
        }
        for index in [1, 2, 0] {
            first
                .reveal(validators[index], reveals[index])
                .expect("reveal");
        }
        for index in [0, 2, 1] {
            second
                .reveal(validators[index], reveals[index])
                .expect("reveal");
        }

        assert_eq!(
            first.finalize(2).expect("outcome"),
            second.finalize(2).expect("outcome")
        );
    }

    #[test]
    fn missing_reveal_is_deterministic_and_reported() {
        let validators = [[1; 32], [2; 32], [3; 32]];
        let reveals = [[11; 32], [12; 32], [13; 32]];
        let mut round = CommitRevealRound::new(8, validators).expect("round");
        for index in 0..3 {
            round
                .commit(
                    validators[index],
                    commitment_for(8, &validators[index], &reveals[index]),
                )
                .expect("commit");
        }
        round.reveal(validators[0], reveals[0]).expect("reveal");
        round.reveal(validators[2], reveals[2]).expect("reveal");
        let outcome = round.finalize(2).expect("threshold reached");
        assert_eq!(outcome.missing_reveals, vec![validators[1]]);
    }
}
