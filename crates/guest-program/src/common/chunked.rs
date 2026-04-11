use std::sync::Arc;

use crate::common::ExecutionError;
use ethrex_common::types::ELASTICITY_MULTIPLIER;
use ethrex_common::types::block_execution_witness::{ExecutionWitness, GuestProgramState};
use ethrex_common::types::validate_block_body;
use ethrex_common::types::{AccountUpdate, Block, ChainConfig, block_access_list::BlockAccessList};
use ethrex_common::{validate_block_access_list_hash, validate_block_pre_execution};
use ethrex_crypto::Crypto;
use ethrex_rlp::decode::RLPDecode;
use ethrex_vm::{Evm, GuestProgramStateWrapper};

pub(crate) struct PreparedChunkedMergeContext {
    pub wrapped_db: GuestProgramStateWrapper,
    pub bal: BlockAccessList,
    pub chain_config: ChainConfig,
}

pub fn decode_header_bal(bytes: &[u8]) -> Result<BlockAccessList, ExecutionError> {
    BlockAccessList::decode(bytes)
        .map_err(|e| ExecutionError::Internal(format!("failed to decode header BAL: {e}")))
}

pub fn checkpoint_system_phase(
    vm: &mut Evm,
    block: &Block,
) -> Result<Vec<AccountUpdate>, ExecutionError> {
    vm.apply_system_calls(&block.header)
        .map_err(ExecutionError::Evm)?;
    vm.get_state_transitions_tx().map_err(ExecutionError::Evm)
}

pub(crate) fn prepare_chunked_merge_context(
    block: &Block,
    execution_witness: ExecutionWitness,
    header_bal: &[u8],
    crypto: Arc<dyn Crypto>,
) -> Result<PreparedChunkedMergeContext, ExecutionError> {
    let bal = decode_header_bal(header_bal)?;
    let chain_config = execution_witness.chain_config.clone();
    if !chain_config.is_amsterdam_activated(block.header.timestamp) {
        return Err(ExecutionError::Internal(
            "chunked BAL proving requires Amsterdam+".to_string(),
        ));
    }

    let wrapped_db = GuestProgramStateWrapper::new(
        GuestProgramState::from_witness(execution_witness, crypto.as_ref())?,
        crypto.clone(),
    );

    wrapped_db.initialize_block_header_hashes(std::slice::from_ref(block))?;
    if let Ok(Some(invalid_block_header)) = wrapped_db.get_first_invalid_block_hash() {
        return Err(ExecutionError::InvalidBlockHash(invalid_block_header));
    }

    let parent_block_header = wrapped_db.get_block_parent_header(block.header.number)?;
    validate_block_body(&block.header, &block.body, crypto.as_ref())
        .map_err(ExecutionError::BlockBodyValidation)?;
    validate_block_pre_execution(
        block,
        &parent_block_header,
        &chain_config,
        ELASTICITY_MULTIPLIER,
    )
    .map_err(ExecutionError::BlockValidation)?;
    validate_block_access_list_hash(
        &block.header,
        &chain_config,
        &bal,
        block.body.transactions.len(),
    )
    .map_err(ExecutionError::BlockValidation)?;

    let initial_state_hash = wrapped_db.state_trie_root()?;
    if initial_state_hash != parent_block_header.state_root {
        return Err(ExecutionError::InvalidInitialStateTrie);
    }

    Ok(PreparedChunkedMergeContext {
        wrapped_db,
        bal,
        chain_config,
    })
}
