use std::sync::Arc;
use std::thread;

use ethrex_common::NativeCrypto;
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
use ethrex_common::types::eip8025_ssz::NewPayloadRequest;
use ethrex_common::types::{Block, TxType};
use ethrex_guest_program::l1::{
    ChunkProgramInput, ChunkProgramOutput, ChunkRange, MergeProgramInput, ProgramOutput,
    chunk_execution_program, merge_execution_program, prepare_new_payload_request,
};
use ethrex_rlp::encode::RLPEncode;

use crate::BackendError;

#[derive(Clone, Debug)]
pub struct ChunkedL1Config {
    pub max_txs_per_chunk: usize,
}

impl Default for ChunkedL1Config {
    fn default() -> Self {
        Self {
            max_txs_per_chunk: 64,
        }
    }
}

pub struct ChunkedL1Execution {
    pub chunk_outputs: Vec<ChunkProgramOutput>,
    pub merge_input: MergeProgramInput,
    pub merge_output: ProgramOutput,
}

pub fn partition_chunk_ranges(
    tx_count: usize,
    max_txs_per_chunk: usize,
) -> Result<Vec<ChunkRange>, BackendError> {
    if max_txs_per_chunk == 0 {
        return Err(BackendError::execution(
            "max_txs_per_chunk must be greater than zero",
        ));
    }

    let mut ranges = Vec::new();
    let mut start = 0usize;
    while start < tx_count {
        let end = (start + max_txs_per_chunk).min(tx_count);
        ranges.push(ChunkRange::new(start as u64, end as u64));
        start = end;
    }

    Ok(ranges)
}

pub fn execute_chunked_l1(
    new_payload_request: NewPayloadRequest,
    execution_witness: ExecutionWitness,
    header_bal: BlockAccessList,
    config: ChunkedL1Config,
) -> Result<ChunkedL1Execution, BackendError> {
    let (block, _) = prepare_new_payload_request(
        &new_payload_request,
        Some(header_bal.compute_hash()),
        &NativeCrypto,
    )
    .map_err(BackendError::execution)?;
    let chunk_ranges =
        partition_chunk_ranges(block.body.transactions.len(), config.max_txs_per_chunk)?;
    let header_bal_bytes = header_bal.encode_to_vec();
    let crypto = Arc::new(NativeCrypto);

    let chunk_outputs = thread::scope(|scope| -> Result<Vec<ChunkProgramOutput>, BackendError> {
        let mut handles = Vec::with_capacity(chunk_ranges.len());
        for range in chunk_ranges {
            let chunk_input = ChunkProgramInput::new(
                block.clone(),
                execution_witness.clone(),
                header_bal_bytes.clone(),
                range,
            );
            let crypto = crypto.clone();
            handles.push(scope.spawn(move || {
                chunk_execution_program(chunk_input, crypto).map_err(BackendError::execution)
            }));
        }

        let mut outputs = Vec::with_capacity(handles.len());
        for handle in handles {
            outputs.push(
                handle
                    .join()
                    .map_err(|_| BackendError::execution("chunk worker panicked"))??,
            );
        }
        outputs.sort_by_key(|output| output.artifact.range.start_tx);
        Ok(outputs)
    })?;

    let merge_input = MergeProgramInput {
        new_payload_request,
        execution_witness,
        header_bal: header_bal_bytes,
        chunk_outputs: chunk_outputs.clone(),
    };
    let merge_output =
        merge_execution_program(merge_input.clone(), crypto).map_err(BackendError::execution)?;

    Ok(ChunkedL1Execution {
        chunk_outputs,
        merge_input,
        merge_output,
    })
}

pub fn non_privileged_transaction_count(block: &Block) -> usize {
    block
        .body
        .transactions
        .iter()
        .filter(|tx| tx.tx_type() != TxType::Privileged)
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ethrex_common::H256;
    use ethrex_common::types::TxType;
    use ethrex_common::types::eip8025_ssz::{Bytes20, ExecutionPayload};
    use ethrex_common::utils::keccak;
    use ethrex_guest_program::l1::{
        CanonicalChunkArtifact, ProgramOutput, TxExecutionSummary, chunk_commitment_hash,
    };
    use ethrex_rlp::encode::RLPEncode;

    #[test]
    fn partitioning_respects_max_chunk_size() {
        let ranges = partition_chunk_ranges(5, 2).expect("chunk partition should succeed");
        assert_eq!(
            ranges,
            vec![
                ChunkRange::new(0, 2),
                ChunkRange::new(2, 4),
                ChunkRange::new(4, 5),
            ]
        );
    }

    #[test]
    fn partitioning_returns_empty_for_zero_tx_block() {
        let ranges = partition_chunk_ranges(0, 3).expect("chunk partition should succeed");
        assert!(ranges.is_empty());
    }

    #[test]
    fn chunk_commitment_is_derived_from_execution_chunk_outputs() {
        let mut execution = ChunkedL1Execution {
            chunk_outputs: vec![
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
                    range: ChunkRange::new(1, 2),
                    tx_summaries: vec![TxExecutionSummary {
                        tx_index: 1,
                        tx_type: u8::from(TxType::Legacy),
                        succeeded: true,
                        gas_spent: 2,
                        gas_used: 2,
                        state_gas_used: 0,
                        logs: vec![],
                    }],
                    observed_touched_addresses: vec![],
                    observed_storage_accesses: vec![],
                }),
            ],
            merge_input: MergeProgramInput {
                new_payload_request: dummy_new_payload_request(),
                execution_witness: ExecutionWitness::default(),
                header_bal: vec![],
                chunk_outputs: vec![],
            },
            merge_output: ProgramOutput {
                new_payload_request_root: [9_u8; 32],
                valid: true,
            },
        };

        let expected = keccak(
            execution
                .chunk_outputs
                .iter()
                .map(|chunk| chunk.artifact_hash)
                .collect::<Vec<_>>()
                .encode_to_vec(),
        );
        assert_eq!(chunk_commitment_hash(&execution.chunk_outputs), expected);

        execution.merge_output = ProgramOutput {
            new_payload_request_root: [0_u8; 32],
            valid: false,
        };
        assert_eq!(chunk_commitment_hash(&execution.chunk_outputs), expected);
    }

    fn dummy_new_payload_request() -> NewPayloadRequest {
        NewPayloadRequest {
            execution_payload: ExecutionPayload {
                parent_hash: [0_u8; 32],
                fee_recipient: Bytes20([0_u8; 20]),
                state_root: [0_u8; 32],
                receipts_root: [0_u8; 32],
                logs_bloom: vec![0_u8; 256].try_into().unwrap(),
                prev_randao: [0_u8; 32],
                block_number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: vec![].try_into().unwrap(),
                base_fee_per_gas: [0_u8; 32],
                block_hash: [0_u8; 32],
                transactions: vec![].try_into().unwrap(),
                withdrawals: vec![].try_into().unwrap(),
                blob_gas_used: 0,
                excess_blob_gas: 0,
                deposit_requests: vec![].try_into().unwrap(),
                withdrawal_requests: vec![].try_into().unwrap(),
                consolidation_requests: vec![].try_into().unwrap(),
            },
            versioned_hashes: vec![].try_into().unwrap(),
            parent_beacon_block_root: [0_u8; 32],
            execution_requests: vec![].try_into().unwrap(),
        }
    }
}
