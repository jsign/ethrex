use ethrex_common::types::{ChainConfig, Fork};

#[cfg(feature = "revm")]
pub use revm::primitives::SpecId;

#[cfg(not(feature = "revm"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpecId {
    FRONTIER = 0,
    FRONTIER_THAWING = 1,
    HOMESTEAD = 2,
    DAO_FORK = 3,
    TANGERINE = 4,
    SPURIOUS_DRAGON = 5,
    BYZANTIUM = 6,
    CONSTANTINOPLE = 7,
    PETERSBURG = 8,
    ISTANBUL = 9,
    MUIR_GLACIER = 10,
    BERLIN = 11,
    LONDON = 12,
    ARROW_GLACIER = 13,
    GRAY_GLACIER = 14,
    MERGE = 15,
    SHANGHAI = 16,
    CANCUN = 17,
    PRAGUE = 18,
    OSAKA = 19,
}

/// Returns the spec id according to the block timestamp and the stored chain config
/// WARNING: Assumes at least Merge fork is active
pub fn spec_id(chain_config: &ChainConfig, block_timestamp: u64) -> SpecId {
    fork_to_spec_id(chain_config.get_fork(block_timestamp))
}

pub fn fork_to_spec_id(fork: Fork) -> SpecId {
    match fork {
        Fork::Frontier => SpecId::FRONTIER,
        Fork::FrontierThawing => SpecId::FRONTIER_THAWING,
        Fork::Homestead => SpecId::HOMESTEAD,
        Fork::DaoFork => SpecId::DAO_FORK,
        Fork::Tangerine => SpecId::TANGERINE,
        Fork::SpuriousDragon => SpecId::SPURIOUS_DRAGON,
        Fork::Byzantium => SpecId::BYZANTIUM,
        Fork::Constantinople => SpecId::CONSTANTINOPLE,
        Fork::Petersburg => SpecId::PETERSBURG,
        Fork::Istanbul => SpecId::ISTANBUL,
        Fork::MuirGlacier => SpecId::MUIR_GLACIER,
        Fork::Berlin => SpecId::BERLIN,
        Fork::London => SpecId::LONDON,
        Fork::ArrowGlacier => SpecId::ARROW_GLACIER,
        Fork::GrayGlacier => SpecId::GRAY_GLACIER,
        Fork::Paris => SpecId::MERGE,
        Fork::Shanghai => SpecId::SHANGHAI,
        Fork::Cancun => SpecId::CANCUN,
        Fork::Prague => SpecId::PRAGUE,
        Fork::Osaka => SpecId::OSAKA,
    }
}

use ethrex_common::Address;

#[cfg(feature = "revm")]
pub fn create_contract_address(from: Address, nonce: u64) -> Address {
    Address::from_slice(
        revm::primitives::Address(from.0.into())
            .create(nonce)
            .0
            .as_ref(),
    )
}

#[cfg(not(feature = "revm"))]
pub fn create_contract_address(from: Address, nonce: u64) -> Address {
    use ethrex_rlp::encode::encode;
    use sha3::{Digest, Keccak256};

    let encoded = encode((from, nonce));
    let hash = Keccak256::digest(&encoded);
    Address::from_slice(&hash[12..])
}
