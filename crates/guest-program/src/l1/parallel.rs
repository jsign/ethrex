use ethrex_common::rkyv_utils::{H160Wrapper, H256Wrapper};
use ethrex_common::types::{
    Log, Receipt, TxType, block_execution_witness::ExecutionWitness, eip8025_ssz::NewPayloadRequest,
};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, H256};
use ethrex_rlp::decode::RLPDecode;
use ethrex_rlp::encode::RLPEncode;
use ethrex_rlp::structs::Encoder;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct ChunkRange {
    pub start_tx: u64,
    pub end_tx_exclusive: u64,
}

impl ChunkRange {
    pub const fn new(start_tx: u64, end_tx_exclusive: u64) -> Self {
        Self {
            start_tx,
            end_tx_exclusive,
        }
    }

    pub fn validate_for_tx_count(&self, tx_count: usize) -> Result<(), String> {
        let start = self.start_tx as usize;
        let end = self.end_tx_exclusive as usize;

        if start >= end {
            return Err("chunk range must be non-empty".to_string());
        }
        if end > tx_count {
            return Err(format!(
                "chunk range end {} exceeds transaction count {tx_count}",
                self.end_tx_exclusive
            ));
        }

        Ok(())
    }

    pub fn tx_count(&self) -> usize {
        self.end_tx_exclusive.saturating_sub(self.start_tx) as usize
    }
}

impl RLPEncode for ChunkRange {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.start_tx)
            .encode_field(&self.end_tx_exclusive)
            .finish();
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct TxExecutionSummary {
    pub tx_index: u64,
    pub tx_type: u8,
    pub succeeded: bool,
    pub gas_spent: u64,
    pub gas_used: u64,
    pub state_gas_used: u64,
    pub logs: Vec<Vec<u8>>,
}

impl TxExecutionSummary {
    pub fn new(
        tx_index: u64,
        tx_type: TxType,
        succeeded: bool,
        gas_spent: u64,
        gas_used: u64,
        state_gas_used: u64,
        logs: &[Log],
    ) -> Self {
        Self {
            tx_index,
            tx_type: tx_type.into(),
            succeeded,
            gas_spent,
            gas_used,
            state_gas_used,
            logs: logs.iter().map(RLPEncode::encode_to_vec).collect(),
        }
    }

    pub fn decode_logs(&self) -> Result<Vec<Log>, String> {
        self.logs
            .iter()
            .map(|log| Log::decode(log).map_err(|e| format!("failed to decode summary log: {e}")))
            .collect()
    }

    pub fn tx_type(&self) -> Result<TxType, String> {
        TxType::from_u8(self.tx_type)
            .ok_or_else(|| format!("invalid tx type in summary: {}", self.tx_type))
    }

    pub fn into_receipt(&self, cumulative_gas_spent: &mut u64) -> Result<Receipt, String> {
        *cumulative_gas_spent = cumulative_gas_spent.saturating_add(self.gas_spent);
        Ok(Receipt::new(
            self.tx_type()?,
            self.succeeded,
            *cumulative_gas_spent,
            self.decode_logs()?,
        ))
    }
}

impl RLPEncode for TxExecutionSummary {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.tx_index)
            .encode_field(&self.tx_type)
            .encode_field(&self.succeeded)
            .encode_field(&self.gas_spent)
            .encode_field(&self.gas_used)
            .encode_field(&self.state_gas_used)
            .encode_field(&self.logs)
            .finish();
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct CanonicalObservedStorageAccess {
    #[rkyv(with = H160Wrapper)]
    pub address: Address,
    #[rkyv(with = H256Wrapper)]
    pub slot: H256,
}

impl RLPEncode for CanonicalObservedStorageAccess {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.address)
            .encode_field(&self.slot)
            .finish();
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct CanonicalObservedAddress {
    #[rkyv(with = H160Wrapper)]
    pub address: Address,
}

impl RLPEncode for CanonicalObservedAddress {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        self.address.encode(buf);
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct CanonicalChunkArtifact {
    #[rkyv(with = H256Wrapper)]
    pub block_hash: H256,
    #[rkyv(with = H256Wrapper)]
    pub bal_hash: H256,
    pub range: ChunkRange,
    pub tx_summaries: Vec<TxExecutionSummary>,
    pub observed_touched_addresses: Vec<CanonicalObservedAddress>,
    pub observed_storage_accesses: Vec<CanonicalObservedStorageAccess>,
}

impl CanonicalChunkArtifact {
    pub fn compute_hash(&self) -> H256 {
        keccak(self.encode_to_vec())
    }

    pub fn validate_shape(&self, tx_count: usize) -> Result<(), String> {
        self.range.validate_for_tx_count(tx_count)?;
        if self.tx_summaries.len() != self.range.tx_count() {
            return Err("chunk summary count does not match range".to_string());
        }

        for (offset, summary) in self.tx_summaries.iter().enumerate() {
            let expected_index = self.range.start_tx + offset as u64;
            if summary.tx_index != expected_index {
                return Err(format!(
                    "chunk summary index {} does not match expected tx index {expected_index}",
                    summary.tx_index
                ));
            }
        }

        for window in self.observed_touched_addresses.windows(2) {
            if window[0].address >= window[1].address {
                return Err("observed touched addresses are not strictly ordered".to_string());
            }
        }

        for window in self.observed_storage_accesses.windows(2) {
            if (window[0].address, window[0].slot) >= (window[1].address, window[1].slot) {
                return Err("observed storage accesses are not strictly ordered".to_string());
            }
        }

        Ok(())
    }
}

impl RLPEncode for CanonicalChunkArtifact {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.block_hash)
            .encode_field(&self.bal_hash)
            .encode_field(&self.range)
            .encode_field(&self.tx_summaries)
            .encode_field(&self.observed_touched_addresses)
            .encode_field(&self.observed_storage_accesses)
            .finish();
    }
}

#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
pub struct ChunkProgramOutput {
    pub artifact: CanonicalChunkArtifact,
    #[rkyv(with = H256Wrapper)]
    pub artifact_hash: H256,
}

impl ChunkProgramOutput {
    pub fn new(artifact: CanonicalChunkArtifact) -> Self {
        let artifact_hash = artifact.compute_hash();
        Self {
            artifact,
            artifact_hash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

impl RLPEncode for ChunkProgramOutput {
    fn encode(&self, buf: &mut dyn bytes::BufMut) {
        Encoder::new(buf)
            .encode_field(&self.artifact)
            .encode_field(&self.artifact_hash)
            .finish();
    }
}

#[derive(Clone)]
pub struct MergeProgramInput {
    pub new_payload_request: NewPayloadRequest,
    pub execution_witness: ExecutionWitness,
    pub header_bal: Vec<u8>,
    pub chunk_outputs: Vec<ChunkProgramOutput>,
}

impl MergeProgramInput {
    pub fn validate_chunk_coverage(&self) -> Result<(), String> {
        validate_chunk_coverage(
            &self.chunk_outputs,
            self.new_payload_request
                .execution_payload
                .transactions
                .len(),
        )
    }
}

pub fn validate_chunk_coverage(
    chunk_outputs: &[ChunkProgramOutput],
    tx_count: usize,
) -> Result<(), String> {
    if tx_count == 0 {
        if chunk_outputs.is_empty() {
            return Ok(());
        }
        return Err("zero-transaction blocks must not include chunk outputs".to_string());
    }

    if chunk_outputs.is_empty() {
        return Err("non-empty blocks must include chunk outputs".to_string());
    }

    let mut expected_start = 0_u64;
    for chunk in chunk_outputs {
        chunk.artifact.validate_shape(tx_count)?;
        if chunk.artifact.range.start_tx != expected_start {
            return Err(format!(
                "chunk coverage gap or overlap at tx {}",
                chunk.artifact.range.start_tx
            ));
        }
        expected_start = chunk.artifact.range.end_tx_exclusive;
    }

    if expected_start != tx_count as u64 {
        return Err(format!(
            "chunk coverage ends at {expected_start}, expected {tx_count}"
        ));
    }

    Ok(())
}

pub fn chunk_commitment_hash(chunk_outputs: &[ChunkProgramOutput]) -> H256 {
    let hashes: Vec<_> = chunk_outputs
        .iter()
        .map(|chunk| chunk.artifact_hash)
        .collect();
    keccak(hashes.encode_to_vec())
}

pub fn build_receipts_from_summaries(
    summaries: &[TxExecutionSummary],
) -> Result<Vec<Receipt>, String> {
    let mut cumulative_gas_spent = 0_u64;
    summaries
        .iter()
        .map(|summary| summary.into_receipt(&mut cumulative_gas_spent))
        .collect()
}

pub fn compute_block_gas_from_summaries(summaries: &[TxExecutionSummary]) -> u64 {
    let regular_gas = summaries.iter().fold(0_u64, |acc, summary| {
        acc.saturating_add(summary.gas_used.saturating_sub(summary.state_gas_used))
    });
    let state_gas = summaries.iter().fold(0_u64, |acc, summary| {
        acc.saturating_add(summary.state_gas_used)
    });
    regular_gas.max(state_gas)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_hash_is_stable() {
        let artifact = CanonicalChunkArtifact {
            block_hash: H256::from_low_u64_be(1),
            bal_hash: H256::from_low_u64_be(2),
            range: ChunkRange::new(0, 1),
            tx_summaries: vec![TxExecutionSummary {
                tx_index: 0,
                tx_type: u8::from(TxType::Legacy),
                succeeded: true,
                gas_spent: 21_000,
                gas_used: 21_000,
                state_gas_used: 0,
                logs: vec![],
            }],
            observed_touched_addresses: vec![CanonicalObservedAddress {
                address: Address::from_low_u64_be(1),
            }],
            observed_storage_accesses: vec![CanonicalObservedStorageAccess {
                address: Address::from_low_u64_be(1),
                slot: H256::from_low_u64_be(7),
            }],
        };

        assert_eq!(artifact.compute_hash(), artifact.compute_hash());
    }

    #[test]
    fn coverage_validation_rejects_gaps() {
        let chunk_outputs = vec![
            ChunkProgramOutput::new(CanonicalChunkArtifact {
                block_hash: H256::from_low_u64_be(1),
                bal_hash: H256::from_low_u64_be(2),
                range: ChunkRange::new(0, 1),
                tx_summaries: vec![TxExecutionSummary {
                    tx_index: 0,
                    tx_type: u8::from(TxType::Legacy),
                    succeeded: true,
                    gas_spent: 1,
                    gas_used: 1,
                    state_gas_used: 0,
                    logs: vec![],
                }],
                observed_touched_addresses: vec![],
                observed_storage_accesses: vec![],
            }),
            ChunkProgramOutput::new(CanonicalChunkArtifact {
                block_hash: H256::from_low_u64_be(1),
                bal_hash: H256::from_low_u64_be(2),
                range: ChunkRange::new(2, 3),
                tx_summaries: vec![TxExecutionSummary {
                    tx_index: 2,
                    tx_type: u8::from(TxType::Legacy),
                    succeeded: true,
                    gas_spent: 1,
                    gas_used: 1,
                    state_gas_used: 0,
                    logs: vec![],
                }],
                observed_touched_addresses: vec![],
                observed_storage_accesses: vec![],
            }),
        ];

        assert!(validate_chunk_coverage(&chunk_outputs, 3).is_err());
    }

    #[test]
    fn coverage_validation_accepts_zero_tx_empty_chunks() {
        assert!(validate_chunk_coverage(&[], 0).is_ok());
    }
}
