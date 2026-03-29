use bytes::Bytes;
use ethrex_crypto::Crypto;
use ethrex_rlp::error::RLPDecodeError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Address, Bloom, H256, serde_utils,
    types::{
        Block, BlockBody, BlockHeader, Transaction, Withdrawal, block_access_list::BlockAccessList,
        compute_transactions_root, compute_withdrawals_root,
    },
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayload {
    pub parent_hash: H256,
    pub fee_recipient: Address,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub prev_randao: H256,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub block_number: u64,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub gas_used: u64,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub timestamp: u64,
    #[serde(with = "serde_utils::bytes")]
    pub extra_data: Bytes,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub base_fee_per_gas: u64,
    pub block_hash: H256,
    pub transactions: Vec<EncodedTransaction>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub withdrawals: Option<Vec<Withdrawal>>,
    // ExecutionPayloadV3 fields. Optional since we support V2 too
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::u64::hex_str_opt",
        default
    )]
    pub blob_gas_used: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::u64::hex_str_opt",
        default
    )]
    pub excess_blob_gas: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::u64::hex_str_opt",
        default
    )]
    pub slot_number: Option<u64>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "serde_utils::block_access_list::rlp_str_opt",
        default
    )]
    pub block_access_list: Option<BlockAccessList>,
}

#[derive(Clone, Debug)]
pub struct EncodedTransaction(pub Bytes);

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExecutionPayloadValidationError {
    #[error("missing field `{field}` in execution payload")]
    MissingField { field: &'static str },
    #[error("unexpected field `{field}` in execution payload")]
    UnexpectedField { field: &'static str },
    #[error("block hash mismatch: expected {expected:#x}, got {actual:#x}")]
    BlockHashMismatch { expected: H256, actual: H256 },
    #[error("blob versioned hashes mismatch: expected {expected:?}, got {actual:?}")]
    BlobVersionedHashesMismatch {
        expected: Vec<H256>,
        actual: Vec<H256>,
    },
}

impl<'de> Deserialize<'de> for EncodedTransaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(EncodedTransaction(serde_utils::bytes::deserialize(
            deserializer,
        )?))
    }
}

impl Serialize for EncodedTransaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde_utils::bytes::serialize(&self.0, serializer)
    }
}

impl EncodedTransaction {
    /// Based on [EIP-2718]
    /// Transactions can be encoded in the following formats:
    /// A) `TransactionType || Transaction`
    /// B) `LegacyTransaction`
    pub fn decode(&self) -> Result<Transaction, RLPDecodeError> {
        Transaction::decode_canonical(self.0.as_ref())
    }

    pub fn encode(tx: &Transaction) -> Self {
        Self(Bytes::from(tx.encode_canonical_to_vec()))
    }
}

impl ExecutionPayload {
    /// Converts an `ExecutionPayload` into a block.
    pub fn into_block(
        self,
        parent_beacon_block_root: Option<H256>,
        requests_hash: Option<H256>,
        block_access_list_hash: Option<H256>,
        crypto: &dyn Crypto,
    ) -> Result<Block, RLPDecodeError> {
        let body = BlockBody {
            transactions: self
                .transactions
                .iter()
                .map(EncodedTransaction::decode)
                .collect::<Result<Vec<_>, RLPDecodeError>>()?,
            ommers: vec![],
            withdrawals: self.withdrawals,
        };
        let header = BlockHeader {
            parent_hash: self.parent_hash,
            ommers_hash: *crate::constants::DEFAULT_OMMERS_HASH,
            coinbase: self.fee_recipient,
            state_root: self.state_root,
            transactions_root: compute_transactions_root(&body.transactions, crypto),
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: 0.into(),
            number: self.block_number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data,
            prev_randao: self.prev_randao,
            nonce: 0,
            base_fee_per_gas: Some(self.base_fee_per_gas),
            withdrawals_root: body
                .withdrawals
                .as_ref()
                .map(|w| compute_withdrawals_root(w, crypto)),
            blob_gas_used: self.blob_gas_used,
            excess_blob_gas: self.excess_blob_gas,
            parent_beacon_block_root,
            requests_hash,
            slot_number: self.slot_number,
            block_access_list_hash,
            ..Default::default()
        };

        Ok(Block::new(header, body))
    }

    pub fn from_block(block: Block, block_access_list: Option<BlockAccessList>) -> Self {
        Self {
            parent_hash: block.header.parent_hash,
            fee_recipient: block.header.coinbase,
            state_root: block.header.state_root,
            receipts_root: block.header.receipts_root,
            logs_bloom: block.header.logs_bloom,
            prev_randao: block.header.prev_randao,
            block_number: block.header.number,
            gas_limit: block.header.gas_limit,
            gas_used: block.header.gas_used,
            timestamp: block.header.timestamp,
            extra_data: block.header.extra_data.clone(),
            base_fee_per_gas: block.header.base_fee_per_gas.unwrap_or_default(),
            block_hash: block.hash(),
            transactions: block
                .body
                .transactions
                .iter()
                .map(EncodedTransaction::encode)
                .collect(),
            withdrawals: block.body.withdrawals,
            blob_gas_used: block.header.blob_gas_used,
            excess_blob_gas: block.header.excess_blob_gas,
            slot_number: block.header.slot_number,
            block_access_list,
        }
    }
}

pub fn validate_execution_payload_v1(
    payload: &ExecutionPayload,
) -> Result<(), ExecutionPayloadValidationError> {
    ensure_field_absent(payload.withdrawals.is_some(), "withdrawals")?;
    ensure_field_absent(payload.blob_gas_used.is_some(), "blob_gas_used")?;
    ensure_field_absent(payload.excess_blob_gas.is_some(), "excess_blob_gas")?;
    Ok(())
}

pub fn validate_execution_payload_v2(
    payload: &ExecutionPayload,
) -> Result<(), ExecutionPayloadValidationError> {
    ensure_field_present(payload.withdrawals.is_some(), "withdrawals")?;
    ensure_field_absent(payload.blob_gas_used.is_some(), "blob_gas_used")?;
    ensure_field_absent(payload.excess_blob_gas.is_some(), "excess_blob_gas")?;
    Ok(())
}

pub fn validate_execution_payload_v3(
    payload: &ExecutionPayload,
) -> Result<(), ExecutionPayloadValidationError> {
    ensure_field_present(payload.withdrawals.is_some(), "withdrawals")?;
    ensure_field_present(payload.blob_gas_used.is_some(), "blob_gas_used")?;
    ensure_field_present(payload.excess_blob_gas.is_some(), "excess_blob_gas")?;
    Ok(())
}

#[inline]
pub fn validate_execution_payload_v4(
    payload: &ExecutionPayload,
) -> Result<(), ExecutionPayloadValidationError> {
    ensure_field_present(payload.block_access_list.is_some(), "block_access_list")?;
    validate_execution_payload_v3(payload)
}

pub fn validate_block_hash(
    payload: &ExecutionPayload,
    block: &Block,
) -> Result<(), ExecutionPayloadValidationError> {
    let expected = block.hash();
    let actual = payload.block_hash;
    if actual != expected {
        return Err(ExecutionPayloadValidationError::BlockHashMismatch { expected, actual });
    }
    Ok(())
}

pub fn validate_blob_versioned_hashes(
    block: &Block,
    expected: &[H256],
) -> Result<(), ExecutionPayloadValidationError> {
    let actual: Vec<H256> = block
        .body
        .transactions
        .iter()
        .flat_map(|tx| tx.blob_versioned_hashes())
        .collect();

    if expected != actual.as_slice() {
        return Err(
            ExecutionPayloadValidationError::BlobVersionedHashesMismatch {
                expected: expected.to_vec(),
                actual,
            },
        );
    }

    Ok(())
}

fn ensure_field_present(
    condition: bool,
    field: &'static str,
) -> Result<(), ExecutionPayloadValidationError> {
    if !condition {
        return Err(ExecutionPayloadValidationError::MissingField { field });
    }
    Ok(())
}

fn ensure_field_absent(
    condition: bool,
    field: &'static str,
) -> Result<(), ExecutionPayloadValidationError> {
    if condition {
        return Err(ExecutionPayloadValidationError::UnexpectedField { field });
    }
    Ok(())
}
