use std::sync::Arc;

use ethrex_common::types::block_access_list::RawAccessObservation;
use ethrex_common::{validate_gas_used, validate_receipts_root, validate_requests_hash};
use ethrex_crypto::Crypto;
use ethrex_vm::Evm;

use crate::common::{ExecutionError, decode_header_bal, prepare_chunked_merge_context};
use crate::l1::output::ProgramOutput;
use crate::l1::parallel::{
    MergeProgramInput, build_receipts_from_summaries, compute_block_gas_from_summaries,
};
use crate::l1::prepare_new_payload_request;

pub fn execution_program(
    input: MergeProgramInput,
    crypto: Arc<dyn Crypto>,
) -> Result<ProgramOutput, ExecutionError> {
    let MergeProgramInput {
        new_payload_request,
        execution_witness,
        header_bal,
        chunk_outputs,
    } = input;
    let header_bal_hash = decode_header_bal(&header_bal)?.compute_hash();
    let (block, new_payload_request_root) =
        prepare_new_payload_request(&new_payload_request, Some(header_bal_hash), crypto.as_ref())?;

    crate::l1::parallel::validate_chunk_coverage(&chunk_outputs, block.body.transactions.len())
        .map_err(ExecutionError::Internal)?;

    let merge_context =
        prepare_chunked_merge_context(&block, execution_witness, &header_bal, crypto.clone())?;
    let mut wrapped_db = merge_context.wrapped_db;
    let bal = merge_context.bal;
    let chain_config = merge_context.chain_config;

    let expected_block_hash = block.header.compute_block_hash(crypto.as_ref());
    let expected_bal_hash = bal.compute_hash();

    let mut observed_accesses = RawAccessObservation::default();
    let mut all_summaries = Vec::with_capacity(block.body.transactions.len());
    for chunk_output in &chunk_outputs {
        let recomputed_hash = chunk_output.artifact.compute_hash();
        if recomputed_hash != chunk_output.artifact_hash {
            return Err(ExecutionError::Internal(
                "chunk artifact hash mismatch".to_string(),
            ));
        }
        if chunk_output.artifact.block_hash != expected_block_hash {
            return Err(ExecutionError::Internal(
                "chunk artifact block hash mismatch".to_string(),
            ));
        }
        if chunk_output.artifact.bal_hash != expected_bal_hash {
            return Err(ExecutionError::Internal(
                "chunk artifact BAL hash mismatch".to_string(),
            ));
        }

        all_summaries.extend(chunk_output.artifact.tx_summaries.clone());
        observed_accesses.touched_addresses.extend(
            chunk_output
                .artifact
                .observed_touched_addresses
                .iter()
                .map(|address| address.address),
        );
        observed_accesses.storage_accesses.extend(
            chunk_output
                .artifact
                .observed_storage_accesses
                .iter()
                .map(|access| (access.address, access.slot)),
        );
    }

    let tx_phase_updates = {
        let mut pre_vm = Evm::new_for_l1(wrapped_db.clone(), crypto.clone());
        pre_vm.enable_bal_recording();
        pre_vm.set_bal_index(0);
        pre_vm
            .apply_system_calls(&block.header)
            .map_err(ExecutionError::Evm)?;
        pre_vm
            .validate_current_state_against_bal_index(&bal, 0, "pre-system phase")
            .map_err(ExecutionError::Evm)?;
        if let Some(observation) = pre_vm.take_raw_access_observation() {
            observed_accesses.extend(observation);
        }
        #[allow(clippy::cast_possible_truncation)]
        let tx_phase_bal_idx = block.body.transactions.len() as u16;
        pre_vm
            .account_updates_from_bal_through_index(&bal, tx_phase_bal_idx)
            .map_err(ExecutionError::Evm)?
    };
    if !tx_phase_updates.is_empty() {
        wrapped_db.apply_account_updates(&tx_phase_updates)?;
    }

    let receipts =
        build_receipts_from_summaries(&all_summaries).map_err(ExecutionError::Internal)?;
    validate_gas_used(
        compute_block_gas_from_summaries(&all_summaries),
        &block.header,
    )
    .map_err(ExecutionError::GasValidation)?;
    validate_receipts_root(&block.header, &receipts, crypto.as_ref())
        .map_err(ExecutionError::ReceiptsRootValidation)?;

    let requests = {
        let mut post_vm = Evm::new_for_l1(wrapped_db.clone(), crypto.clone());
        post_vm.enable_bal_recording();
        #[allow(clippy::cast_possible_truncation)]
        let post_bal_idx = (block.body.transactions.len() + 1) as u16;
        post_vm.set_bal_index(post_bal_idx);
        if let Some(withdrawals) = &block.body.withdrawals
            && let Some(recorder) = post_vm.db.bal_recorder_mut()
        {
            recorder.extend_touched_addresses(withdrawals.iter().map(|w| w.address));
        }
        let requests = post_vm
            .extract_requests(&receipts, &block.header)
            .map_err(ExecutionError::Evm)?;
        if let Some(withdrawals) = &block.body.withdrawals {
            post_vm
                .process_withdrawals(withdrawals)
                .map_err(ExecutionError::Evm)?;
        }
        post_vm
            .validate_current_state_against_bal_index(
                &bal,
                post_bal_idx,
                "withdrawal/request phase",
            )
            .map_err(ExecutionError::Evm)?;
        if let Some(observation) = post_vm.take_raw_access_observation() {
            observed_accesses.extend(observation);
        }
        let post_updates = post_vm
            .get_state_transitions()
            .map_err(ExecutionError::Evm)?;
        if !post_updates.is_empty() {
            wrapped_db.apply_account_updates(&post_updates)?;
        }
        requests
    };

    validate_requests_hash(&block.header, &chain_config, &requests)
        .map_err(ExecutionError::RequestsRootValidation)?;
    Evm::validate_raw_access_observation(&bal, &observed_accesses).map_err(ExecutionError::Evm)?;

    let final_state_hash = wrapped_db.state_trie_root()?;
    if final_state_hash != block.header.state_root {
        return Err(ExecutionError::InvalidFinalStateTrie);
    }

    Ok(ProgramOutput {
        new_payload_request_root,
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::l1::{CanonicalChunkArtifact, ChunkProgramOutput, ChunkRange, TxExecutionSummary};
    use bytes::Bytes;
    use ethrex_common::constants::{
        DEFAULT_OMMERS_HASH, EMPTY_BLOCK_ACCESS_LIST_HASH, EMPTY_TRIE_HASH, EMPTY_WITHDRAWALS_HASH,
    };
    use ethrex_common::types::block_access_list::{AccountChanges, BalanceChange, BlockAccessList};
    use ethrex_common::types::block_execution_witness::{ExecutionWitness, GuestProgramState};
    use ethrex_common::types::eip8025_ssz::{
        Bytes20, ExecutionPayload, NewPayloadRequest, Withdrawal as SszWithdrawal,
    };
    use ethrex_common::types::requests::{EncodedRequests, compute_requests_hash};
    use ethrex_common::types::{
        AccountState, Block, BlockBody, BlockHeader, ChainConfig, Code, GWEI_TO_WEI,
        LegacyTransaction, Transaction, TxKind, TxType, Withdrawal, compute_receipts_root,
        compute_transactions_root, compute_withdrawals_root,
    };
    use ethrex_common::{Address, H256, U256};
    use ethrex_rlp::encode::RLPEncode;
    use ethrex_trie::{Node, Trie};
    use ethrex_vm::GuestProgramStateWrapper;
    use ethrex_vm::system_contracts::{
        BEACON_ROOTS_ADDRESS, CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS, HISTORY_STORAGE_ADDRESS,
        WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
    };
    use libssz_merkle::{HashTreeRoot, Sha2Hasher};
    use std::collections::BTreeMap;

    fn amsterdam_chain_config() -> ChainConfig {
        ChainConfig {
            chain_id: 1,
            shanghai_time: Some(0),
            cancun_time: Some(0),
            prague_time: Some(0),
            amsterdam_time: Some(0),
            ..Default::default()
        }
    }

    fn make_parent_header(state_root: H256) -> BlockHeader {
        BlockHeader {
            ommers_hash: *DEFAULT_OMMERS_HASH,
            state_root,
            transactions_root: *EMPTY_TRIE_HASH,
            receipts_root: *EMPTY_TRIE_HASH,
            withdrawals_root: Some(*EMPTY_WITHDRAWALS_HASH),
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            base_fee_per_gas: Some(7),
            ..Default::default()
        }
    }

    fn make_empty_block(parent_header: &BlockHeader) -> Block {
        make_empty_block_with_bal(parent_header, &BlockAccessList::new())
    }

    fn make_empty_block_with_bal(parent_header: &BlockHeader, bal: &BlockAccessList) -> Block {
        let empty_requests: Vec<EncodedRequests> = vec![];
        let body = BlockBody::empty();
        let header = BlockHeader {
            parent_hash: parent_header.hash(),
            ommers_hash: *DEFAULT_OMMERS_HASH,
            state_root: *EMPTY_TRIE_HASH,
            transactions_root: *EMPTY_TRIE_HASH,
            receipts_root: *EMPTY_TRIE_HASH,
            withdrawals_root: Some(*EMPTY_WITHDRAWALS_HASH),
            number: 1,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 1,
            extra_data: Bytes::new(),
            base_fee_per_gas: Some(7),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(H256::zero()),
            requests_hash: Some(compute_requests_hash(&empty_requests)),
            block_access_list_hash: Some(if bal.accounts().is_empty() {
                *EMPTY_BLOCK_ACCESS_LIST_HASH
            } else {
                bal.compute_hash()
            }),
            ..Default::default()
        };
        Block::new(header, body)
    }

    fn make_request(block: &Block) -> NewPayloadRequest {
        let mut base_fee_per_gas = [0_u8; 32];
        base_fee_per_gas[..8].copy_from_slice(
            &block
                .header
                .base_fee_per_gas
                .unwrap_or_default()
                .to_le_bytes(),
        );

        NewPayloadRequest {
            execution_payload: ExecutionPayload {
                parent_hash: block.header.parent_hash.to_fixed_bytes(),
                fee_recipient: Bytes20([0_u8; 20]),
                state_root: block.header.state_root.to_fixed_bytes(),
                receipts_root: block.header.receipts_root.to_fixed_bytes(),
                logs_bloom: vec![0_u8; 256].try_into().unwrap(),
                prev_randao: block.header.prev_randao.to_fixed_bytes(),
                block_number: block.header.number,
                gas_limit: block.header.gas_limit,
                gas_used: block.header.gas_used,
                timestamp: block.header.timestamp,
                extra_data: block.header.extra_data.to_vec().try_into().unwrap(),
                base_fee_per_gas,
                block_hash: block
                    .header
                    .compute_block_hash(&ethrex_crypto::NativeCrypto)
                    .to_fixed_bytes(),
                transactions: block
                    .body
                    .transactions
                    .iter()
                    .map(|tx| tx.encode_canonical_to_vec().try_into().unwrap())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                withdrawals: block
                    .body
                    .withdrawals
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|withdrawal| SszWithdrawal {
                        index: withdrawal.index,
                        validator_index: withdrawal.validator_index,
                        address: Bytes20(withdrawal.address.to_fixed_bytes()),
                        amount: withdrawal.amount,
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                blob_gas_used: block.header.blob_gas_used.unwrap_or_default(),
                excess_blob_gas: block.header.excess_blob_gas.unwrap_or_default(),
                deposit_requests: vec![].try_into().unwrap(),
                withdrawal_requests: vec![].try_into().unwrap(),
                consolidation_requests: vec![].try_into().unwrap(),
            },
            versioned_hashes: vec![].try_into().unwrap(),
            parent_beacon_block_root: block
                .header
                .parent_beacon_block_root
                .unwrap_or_default()
                .to_fixed_bytes(),
            execution_requests: vec![].try_into().unwrap(),
        }
    }

    fn make_empty_request(block: &Block) -> NewPayloadRequest {
        make_request(block)
    }

    fn make_merge_input_with_witness_state(
        parent_header: BlockHeader,
        new_payload_request: NewPayloadRequest,
        witness_current_header: BlockHeader,
        chain_config: ChainConfig,
        codes: Vec<Vec<u8>>,
        state_trie_root: Option<Node>,
    ) -> MergeProgramInput {
        MergeProgramInput {
            new_payload_request,
            execution_witness: ExecutionWitness {
                codes,
                block_headers_bytes: vec![
                    parent_header.encode_to_vec(),
                    witness_current_header.encode_to_vec(),
                ],
                first_block_number: 1,
                chain_config,
                state_trie_root,
                storage_trie_roots: BTreeMap::new(),
            },
            header_bal: BlockAccessList::new().encode_to_vec(),
            chunk_outputs: vec![],
        }
    }

    fn make_merge_input(
        parent_header: BlockHeader,
        new_payload_request: NewPayloadRequest,
        witness_current_header: BlockHeader,
        chain_config: ChainConfig,
    ) -> MergeProgramInput {
        make_merge_input_with_witness_state(
            parent_header,
            new_payload_request,
            witness_current_header,
            chain_config,
            vec![],
            None,
        )
    }

    fn valid_merge_input() -> MergeProgramInput {
        valid_merge_input_with_bal(BlockAccessList::new())
    }

    fn valid_merge_input_with_bal(bal: BlockAccessList) -> MergeProgramInput {
        let parent_header = make_parent_header(*EMPTY_TRIE_HASH);
        let block = make_empty_block_with_bal(&parent_header, &bal);
        let mut input = make_merge_input(
            parent_header,
            make_empty_request(&block),
            block.header.clone(),
            amsterdam_chain_config(),
        );
        input.header_bal = bal.encode_to_vec();
        input
    }

    fn request_predeploy_witness_components() -> (Vec<Vec<u8>>, Option<Node>, H256) {
        let bytecode = vec![0x00];
        let code = Code::from_bytecode(Bytes::from(bytecode.clone()), &ethrex_crypto::NativeCrypto);
        let mut trie = Trie::new_temp();

        for address in [
            WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address,
            CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address,
        ] {
            let account_state = AccountState {
                nonce: 1,
                balance: U256::zero(),
                storage_root: *EMPTY_TRIE_HASH,
                code_hash: code.hash,
            };
            let hashed_address = ethrex_common::utils::keccak(address.as_bytes());
            trie.insert(
                hashed_address.as_bytes().to_vec(),
                account_state.encode_to_vec(),
            )
            .expect("predeploy account insertion should succeed");
        }

        let state_root = trie.hash_no_commit(&ethrex_crypto::NativeCrypto);
        let root = trie
            .root_node()
            .expect("state trie root node should exist")
            .map(|node| (*node).clone());

        (vec![bytecode], root, state_root)
    }

    fn compute_final_state_root(
        parent_header: &BlockHeader,
        block: &Block,
        bal: &BlockAccessList,
        summaries: &[TxExecutionSummary],
        chain_config: ChainConfig,
        codes: Vec<Vec<u8>>,
        state_trie_root: Option<Node>,
    ) -> H256 {
        let crypto = Arc::new(ethrex_crypto::NativeCrypto);
        let execution_witness = ExecutionWitness {
            codes,
            block_headers_bytes: vec![parent_header.encode_to_vec(), block.header.encode_to_vec()],
            first_block_number: block.header.number,
            chain_config,
            state_trie_root,
            storage_trie_roots: BTreeMap::new(),
        };
        let guest_state = GuestProgramState::from_witness(execution_witness, crypto.as_ref())
            .expect("test witness should decode");
        let mut wrapped_db = GuestProgramStateWrapper::new(guest_state, crypto.clone());
        wrapped_db
            .initialize_block_header_hashes(std::slice::from_ref(block))
            .expect("block hash initialization should succeed");

        #[allow(clippy::cast_possible_truncation)]
        let tx_phase_bal_idx = block.body.transactions.len() as u16;
        let tx_phase_vm = Evm::new_for_l1(wrapped_db.clone(), crypto.clone());
        let tx_phase_updates = tx_phase_vm
            .account_updates_from_bal_through_index(bal, tx_phase_bal_idx)
            .expect("BAL-derived tx phase state should build");
        if !tx_phase_updates.is_empty() {
            wrapped_db
                .apply_account_updates(&tx_phase_updates)
                .expect("tx phase updates should apply");
        }

        let receipts =
            build_receipts_from_summaries(summaries).expect("test summaries should build receipts");
        let mut post_vm = Evm::new_for_l1(wrapped_db.clone(), crypto);
        let _requests = post_vm
            .extract_requests(&receipts, &block.header)
            .expect("request extraction should succeed");
        if let Some(withdrawals) = &block.body.withdrawals {
            post_vm
                .process_withdrawals(withdrawals)
                .expect("withdrawals should succeed");
        }
        let post_updates = post_vm
            .get_state_transitions()
            .expect("post phase updates should build");
        if !post_updates.is_empty() {
            wrapped_db
                .apply_account_updates(&post_updates)
                .expect("post phase updates should apply");
        }

        wrapped_db
            .state_trie_root()
            .expect("state root should compute")
    }

    fn merge_err(input: MergeProgramInput) -> ExecutionError {
        match execution_program(input, Arc::new(ethrex_crypto::NativeCrypto)) {
            Ok(_) => panic!("merge execution unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    #[test]
    fn merge_returns_standard_eip8025_program_output_type() {
        let merge_execution_program: fn(
            MergeProgramInput,
            Arc<dyn ethrex_crypto::Crypto>,
        ) -> Result<ProgramOutput, ExecutionError> = execution_program;

        let _ = merge_execution_program;
    }

    #[test]
    fn merge_rejects_non_amsterdam_chunked_inputs() {
        let mut input = valid_merge_input();
        input.execution_witness.chain_config.amsterdam_time = None;

        let err = merge_err(input);

        match err {
            ExecutionError::Internal(message) => {
                assert!(message.contains("chunked BAL proving requires Amsterdam+"));
            }
            other => panic!("unexpected error for Amsterdam check: {other:?}"),
        }
    }

    #[test]
    fn merge_request_preparation_returns_request_root_for_valid_input() {
        let input = valid_merge_input();
        let expected_root = input.new_payload_request.hash_tree_root(&Sha2Hasher);
        let bal_hash = crate::common::decode_header_bal(&input.header_bal)
            .expect("BAL should decode")
            .compute_hash();

        let (_block, request_root) = prepare_new_payload_request(
            &input.new_payload_request,
            Some(bal_hash),
            &ethrex_crypto::NativeCrypto,
        )
        .expect("request preparation should succeed");

        assert_eq!(request_root, expected_root);
    }

    #[test]
    fn merge_rejects_payload_block_hash_mismatch() {
        let mut input = valid_merge_input();
        input.new_payload_request.execution_payload.block_hash = [9_u8; 32];

        let err = merge_err(input);

        match err {
            ExecutionError::Internal(message) => {
                assert!(message.contains("block_hash mismatch"));
            }
            other => panic!("unexpected error for payload block-hash validation: {other:?}"),
        }
    }

    #[test]
    fn merge_rejects_invalid_versioned_hashes() {
        let mut input = valid_merge_input();
        input.new_payload_request.versioned_hashes = vec![[7_u8; 32]].try_into().unwrap();

        let err = merge_err(input);

        match err {
            ExecutionError::Internal(message) => {
                assert!(message.contains("versioned hashes mismatch"));
            }
            other => panic!("unexpected error for versioned-hash validation: {other:?}"),
        }
    }

    #[test]
    fn merge_rejects_invalid_block_hash_linkage() {
        let parent_header = make_parent_header(*EMPTY_TRIE_HASH);
        let block = make_empty_block(&parent_header);
        let mut witness_current_header = block.header.clone();
        witness_current_header.parent_hash = H256::from_low_u64_be(9);
        let input = make_merge_input(
            parent_header,
            make_empty_request(&block),
            witness_current_header,
            amsterdam_chain_config(),
        );

        let err = merge_err(input);

        match err {
            ExecutionError::InvalidBlockHash(0) => {}
            other => panic!("unexpected error for block-hash linkage: {other:?}"),
        }
    }

    #[test]
    fn merge_rejects_invalid_initial_state_root_witness() {
        let parent_header = make_parent_header(H256::from_low_u64_be(11));
        let block = make_empty_block(&parent_header);
        let input = make_merge_input(
            parent_header,
            make_empty_request(&block),
            block.header.clone(),
            amsterdam_chain_config(),
        );

        let err = merge_err(input);

        match err {
            ExecutionError::InvalidInitialStateTrie => {}
            other => panic!("unexpected error for initial state validation: {other:?}"),
        }
    }

    #[test]
    fn merge_rejects_unobserved_pre_system_bal_change() {
        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(Address::from_low_u64_be(1))
                .with_balance_changes(vec![BalanceChange::new(0, 1_u64.into())]),
        ]);
        let err = merge_err(valid_merge_input_with_bal(bal));

        match err {
            ExecutionError::Evm(ethrex_vm::EvmError::Custom(message)) => {
                assert!(message.contains("pre-system phase"));
                assert!(message.contains("index 0"));
            }
            other => panic!("unexpected error for pre-system BAL mismatch: {other:?}"),
        }
    }

    #[test]
    fn merge_accepts_bal_backed_tx_state_without_chunk_updates() {
        let chain_config = amsterdam_chain_config();
        let (codes, state_trie_root, initial_state_root) = request_predeploy_witness_components();
        let parent_header = make_parent_header(initial_state_root);
        let tx = Transaction::LegacyTransaction(LegacyTransaction {
            nonce: 0,
            gas_price: U256::from(10_u64),
            gas: 21_000,
            to: TxKind::Call(Address::from_low_u64_be(2)),
            value: U256::from(1_u64),
            ..Default::default()
        });
        let summary = TxExecutionSummary {
            tx_index: 0,
            tx_type: u8::from(TxType::Legacy),
            succeeded: true,
            gas_spent: 21_000,
            gas_used: 21_000,
            state_gas_used: 0,
            logs: vec![],
        };
        let summaries = vec![summary.clone()];
        let receipts = build_receipts_from_summaries(&summaries).expect("receipts should build");
        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(Address::from_low_u64_be(7))
                .with_balance_changes(vec![BalanceChange::new(1, U256::from(5_u64))]),
            AccountChanges::new(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address),
            AccountChanges::new(CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address),
            AccountChanges::new(HISTORY_STORAGE_ADDRESS.address),
            AccountChanges::new(BEACON_ROOTS_ADDRESS.address),
        ]);
        let empty_requests: Vec<EncodedRequests> = vec![];
        let body = BlockBody {
            transactions: vec![tx],
            ommers: vec![],
            withdrawals: Some(vec![]),
        };
        let mut block = Block::new(
            BlockHeader {
                parent_hash: parent_header.hash(),
                ommers_hash: *DEFAULT_OMMERS_HASH,
                state_root: H256::zero(),
                transactions_root: compute_transactions_root(
                    &body.transactions,
                    &ethrex_crypto::NativeCrypto,
                ),
                receipts_root: compute_receipts_root(&receipts, &ethrex_crypto::NativeCrypto),
                withdrawals_root: Some(compute_withdrawals_root(
                    body.withdrawals.as_deref().unwrap_or(&[]),
                    &ethrex_crypto::NativeCrypto,
                )),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: compute_block_gas_from_summaries(&summaries),
                timestamp: 1,
                extra_data: Bytes::new(),
                base_fee_per_gas: Some(7),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(H256::zero()),
                requests_hash: Some(compute_requests_hash(&empty_requests)),
                block_access_list_hash: Some(bal.compute_hash()),
                ..Default::default()
            },
            body,
        );
        block.header.state_root = compute_final_state_root(
            &parent_header,
            &block,
            &bal,
            &summaries,
            chain_config.clone(),
            codes.clone(),
            state_trie_root.clone(),
        );

        let mut input = make_merge_input_with_witness_state(
            parent_header,
            make_request(&block),
            block.header.clone(),
            chain_config,
            codes,
            state_trie_root,
        );
        input.header_bal = bal.encode_to_vec();
        input.chunk_outputs = vec![ChunkProgramOutput::new(CanonicalChunkArtifact {
            block_hash: block
                .header
                .compute_block_hash(&ethrex_crypto::NativeCrypto),
            bal_hash: bal.compute_hash(),
            range: ChunkRange::new(0, 1),
            tx_summaries: summaries,
            observed_touched_addresses: vec![],
            observed_storage_accesses: vec![],
        })];

        let output = execution_program(input, Arc::new(ethrex_crypto::NativeCrypto))
            .expect("merge should reconstruct tx-phase state from BAL");
        assert!(output.valid);
    }

    #[test]
    fn merge_applies_post_phase_bal_changes_after_tx_phase_reconstruction() {
        let chain_config = amsterdam_chain_config();
        let (codes, state_trie_root, initial_state_root) = request_predeploy_witness_components();
        let parent_header = make_parent_header(initial_state_root);
        let withdrawals = vec![Withdrawal {
            index: 0,
            validator_index: 0,
            address: Address::from_low_u64_be(9),
            amount: 2,
        }];
        let post_withdrawal_balance =
            U256::from(u128::from(withdrawals[0].amount) * u128::from(GWEI_TO_WEI));
        let bal = BlockAccessList::from_accounts(vec![
            AccountChanges::new(withdrawals[0].address)
                .with_balance_changes(vec![BalanceChange::new(1, post_withdrawal_balance)]),
            AccountChanges::new(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address),
            AccountChanges::new(CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS.address),
            AccountChanges::new(HISTORY_STORAGE_ADDRESS.address),
            AccountChanges::new(BEACON_ROOTS_ADDRESS.address),
        ]);
        let empty_requests: Vec<EncodedRequests> = vec![];
        let body = BlockBody {
            transactions: vec![],
            ommers: vec![],
            withdrawals: Some(withdrawals.clone()),
        };
        let summaries = vec![];
        let receipts = build_receipts_from_summaries(&summaries).expect("receipts should build");
        let mut block = Block::new(
            BlockHeader {
                parent_hash: parent_header.hash(),
                ommers_hash: *DEFAULT_OMMERS_HASH,
                state_root: H256::zero(),
                transactions_root: compute_transactions_root(
                    &body.transactions,
                    &ethrex_crypto::NativeCrypto,
                ),
                receipts_root: compute_receipts_root(&receipts, &ethrex_crypto::NativeCrypto),
                withdrawals_root: Some(compute_withdrawals_root(
                    body.withdrawals.as_deref().unwrap_or(&[]),
                    &ethrex_crypto::NativeCrypto,
                )),
                number: 1,
                gas_limit: 30_000_000,
                gas_used: 0,
                timestamp: 1,
                extra_data: Bytes::new(),
                base_fee_per_gas: Some(7),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: Some(H256::zero()),
                requests_hash: Some(compute_requests_hash(&empty_requests)),
                block_access_list_hash: Some(bal.compute_hash()),
                ..Default::default()
            },
            body,
        );
        block.header.state_root = compute_final_state_root(
            &parent_header,
            &block,
            &bal,
            &summaries,
            chain_config.clone(),
            codes.clone(),
            state_trie_root.clone(),
        );

        let mut input = make_merge_input_with_witness_state(
            parent_header,
            make_request(&block),
            block.header.clone(),
            chain_config,
            codes,
            state_trie_root,
        );
        input.header_bal = bal.encode_to_vec();

        let output = execution_program(input, Arc::new(ethrex_crypto::NativeCrypto))
            .expect("merge should apply post-phase BAL changes after tx-phase reconstruction");
        assert!(output.valid);
    }
}
