use std::sync::Arc;

use ethrex_common::types::Block;
use ethrex_common::types::block_execution_witness::ExecutionWitness;
use ethrex_crypto::Crypto;
use ethrex_vm::{Evm, GuestProgramStateWrapper};

use crate::common::{ExecutionError, checkpoint_system_phase, decode_header_bal};
use crate::l1::parallel::{
    CanonicalChunkArtifact, CanonicalObservedAddress, CanonicalObservedStorageAccess,
    ChunkProgramOutput, ChunkRange, TxExecutionSummary,
};

/// Input for a BAL-backed chunk execution over a single Amsterdam+ block.
///
/// The chunk program assumes block-global validity for `(block, execution_witness, header_bal)`
/// is enforced by the merge program.
#[derive(
    Clone,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Deserialize,
    rkyv::Serialize,
    rkyv::Archive,
)]
pub struct ChunkProgramInput {
    pub block: Block,
    pub execution_witness: ExecutionWitness,
    /// Canonical RLP encoding of the header BAL.
    pub header_bal: Vec<u8>,
    pub range: ChunkRange,
}

impl ChunkProgramInput {
    pub fn new(
        block: Block,
        execution_witness: ExecutionWitness,
        header_bal: Vec<u8>,
        range: ChunkRange,
    ) -> Self {
        Self {
            block,
            execution_witness,
            header_bal,
            range,
        }
    }
}

/// Executes a single tx range assuming block-global validity is checked by merge.
pub fn execution_program(
    input: ChunkProgramInput,
    crypto: Arc<dyn Crypto>,
) -> Result<ChunkProgramOutput, ExecutionError> {
    let ChunkProgramInput {
        block,
        execution_witness,
        header_bal,
        range,
    } = input;

    range
        .validate_for_tx_count(block.body.transactions.len())
        .map_err(ExecutionError::Internal)?;

    let bal = decode_header_bal(&header_bal)?;

    let guest_state =
        ethrex_common::types::block_execution_witness::GuestProgramState::from_witness(
            execution_witness,
            crypto.as_ref(),
        )
        .map_err(ExecutionError::GuestProgramState)?;
    let wrapped_db = GuestProgramStateWrapper::new(guest_state, crypto.clone());

    wrapped_db.initialize_block_header_hashes(std::slice::from_ref(&block))?;

    let mut vm = Evm::new_for_l1(wrapped_db, crypto.clone());
    let _system_updates = checkpoint_system_phase(&mut vm, &block)?;
    let system_seed = vm.db.initial_accounts_state.clone();
    let validation_index = bal.build_validation_index();

    #[allow(clippy::cast_possible_truncation)]
    vm.seed_chunk_start_from_bal(&bal, range.start_tx as u16, &validation_index)
        .map_err(ExecutionError::Evm)?;
    vm.enable_bal_recording();

    let txs_with_sender = block
        .body
        .get_transactions_with_sender(crypto.as_ref())
        .map_err(|e| {
            ExecutionError::Internal(format!("failed to recover transaction senders: {e}"))
        })?;

    let mut tx_summaries = Vec::with_capacity(range.tx_count());
    let mut cumulative_gas_spent = 0_u64;
    for tx_idx in range.start_tx as usize..range.end_tx_exclusive as usize {
        let (tx, sender) = txs_with_sender[tx_idx];
        #[allow(clippy::cast_possible_truncation)]
        vm.set_bal_index((tx_idx + 1) as u16);
        if let Some(recorder) = vm.db.bal_recorder_mut() {
            recorder.record_touched_address(sender);
            if let ethrex_common::types::TxKind::Call(to) = tx.to() {
                recorder.record_touched_address(to);
            }
        }
        let (_receipt, report) = vm
            .execute_tx(tx, &block.header, &mut cumulative_gas_spent, sender)
            .map_err(ExecutionError::Evm)?;

        #[allow(clippy::cast_possible_truncation)]
        vm.validate_current_tx_against_bal(
            &bal,
            &validation_index,
            &system_seed,
            (tx_idx + 1) as u16,
            tx_idx as u16,
        )
        .map_err(ExecutionError::Evm)?;

        tx_summaries.push(TxExecutionSummary::new(
            tx_idx as u64,
            tx.tx_type(),
            report.is_success(),
            report.gas_spent,
            report.gas_used,
            report.state_gas_used,
            &report.logs,
        ));
    }

    let observation = vm.take_raw_access_observation().unwrap_or_default();
    let observed_touched_addresses = observation
        .touched_addresses
        .into_iter()
        .map(|address| CanonicalObservedAddress { address })
        .collect();
    let observed_storage_accesses = observation
        .storage_accesses
        .into_iter()
        .map(|(address, slot)| CanonicalObservedStorageAccess { address, slot })
        .collect();

    let artifact = CanonicalChunkArtifact {
        block_hash: block.header.compute_block_hash(crypto.as_ref()),
        bal_hash: bal.compute_hash(),
        range,
        tx_summaries,
        observed_touched_addresses,
        observed_storage_accesses,
    };
    artifact
        .validate_shape(block.body.transactions.len())
        .map_err(ExecutionError::Internal)?;

    Ok(ChunkProgramOutput::new(artifact))
}

#[cfg(test)]
mod tests {
    use super::*;

    use ethrex_common::constants::{DEFAULT_OMMERS_HASH, EMPTY_TRIE_HASH};
    use ethrex_common::types::block_access_list::{
        AccountChanges, BalanceChange, BlockAccessList, CodeChange, NonceChange,
    };
    use ethrex_common::types::transaction::GLOBAL_SIGNER_CACHE;
    use ethrex_common::types::{BlockBody, BlockHeader, ChainConfig};
    use ethrex_common::types::{LegacyTransaction, Transaction, TxKind, compute_transactions_root};
    use ethrex_common::{Address, U256};
    use ethrex_crypto::NativeCrypto;
    use ethrex_rlp::encode::RLPEncode;
    use std::collections::BTreeMap;

    fn amsterdam_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            amsterdam_time: Some(0),
            ..Default::default()
        }
    }

    fn make_parent_header(state_root: ethrex_common::H256) -> BlockHeader {
        BlockHeader {
            ommers_hash: *DEFAULT_OMMERS_HASH,
            state_root,
            transactions_root: *EMPTY_TRIE_HASH,
            receipts_root: *EMPTY_TRIE_HASH,
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            base_fee_per_gas: Some(7),
            ..Default::default()
        }
    }

    fn make_cached_sender_tx(sender: Address) -> Transaction {
        let tx = Transaction::LegacyTransaction(LegacyTransaction {
            gas: 21_000,
            gas_price: U256::from(10_u64),
            to: TxKind::Call(Address::from_low_u64_be(2)),
            ..Default::default()
        });
        GLOBAL_SIGNER_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .put(tx.hash(), sender);
        tx
    }

    fn make_bal_mismatch_input() -> ChunkProgramInput {
        let sender = Address::from_low_u64_be(1);
        let tx = make_cached_sender_tx(sender);
        let block_access_list = BlockAccessList::from_accounts(vec![
            AccountChanges::new(sender)
                .with_balance_changes(vec![BalanceChange::new(0, U256::from(1_000_000_u64))])
                .with_nonce_changes(vec![NonceChange::new(0, 0)])
                .with_code_changes(vec![CodeChange::new(0, Vec::new().into())]),
        ]);

        let parent_header = make_parent_header(*EMPTY_TRIE_HASH);
        let block_body = BlockBody {
            transactions: vec![tx],
            ommers: vec![],
            withdrawals: Some(vec![]),
        };
        let block_header = BlockHeader {
            parent_hash: parent_header.hash(),
            ommers_hash: *DEFAULT_OMMERS_HASH,
            state_root: *EMPTY_TRIE_HASH,
            transactions_root: compute_transactions_root(&block_body.transactions, &NativeCrypto),
            receipts_root: *EMPTY_TRIE_HASH,
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1,
            base_fee_per_gas: Some(7),
            ..Default::default()
        };
        let block = Block::new(block_header, block_body);

        let execution_witness = ExecutionWitness {
            codes: vec![],
            block_headers_bytes: vec![parent_header.encode_to_vec(), block.header.encode_to_vec()],
            first_block_number: block.header.number,
            chain_config: amsterdam_chain_config(),
            state_trie_root: None,
            storage_trie_roots: BTreeMap::new(),
        };

        ChunkProgramInput::new(
            block,
            execution_witness,
            block_access_list.encode_to_vec(),
            ChunkRange::new(0, 1),
        )
    }

    #[test]
    fn chunk_rejects_invalid_range() {
        let err = execution_program(
            ChunkProgramInput::new(
                Block::default(),
                ExecutionWitness::default(),
                vec![],
                ChunkRange::new(0, 0),
            ),
            Arc::new(NativeCrypto),
        )
        .expect_err("invalid chunk range should fail before execution");

        match err {
            ExecutionError::Internal(message) => {
                assert!(message.contains("chunk range must be non-empty"));
            }
            other => panic!("unexpected error for invalid range: {other:?}"),
        }
    }

    #[test]
    fn chunk_rejects_malformed_bal_bytes() {
        let mut input = make_bal_mismatch_input();
        input.header_bal = vec![0xff];

        let err = execution_program(input, Arc::new(NativeCrypto))
            .expect_err("malformed BAL bytes should fail during decode");

        match err {
            ExecutionError::Internal(message) => {
                assert!(message.contains("failed to decode header BAL"));
            }
            other => panic!("unexpected error for malformed BAL: {other:?}"),
        }
    }

    #[test]
    fn chunk_still_rejects_per_tx_bal_mismatches() {
        let err = execution_program(make_bal_mismatch_input(), Arc::new(NativeCrypto))
            .expect_err("missing BAL entry should fail after tx execution");

        match err {
            ExecutionError::Evm(ethrex_vm::EvmError::Custom(message)) => {
                assert!(message.contains("balance changed by execution"));
            }
            other => panic!("unexpected error for BAL mismatch: {other:?}"),
        }
    }
}
