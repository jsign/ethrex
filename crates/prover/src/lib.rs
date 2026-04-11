pub mod backend;
#[cfg(feature = "eip-8025")]
pub mod chunked_l1;
pub mod protocol;
pub mod prover;

pub use crate::backend::{BackendError, BackendType, ExecBackend, ProverBackend};
#[cfg(feature = "eip-8025")]
pub use crate::chunked_l1::{
    ChunkedL1Config, ChunkedL1Execution, execute_chunked_l1, non_privileged_transaction_count,
    partition_chunk_ranges,
};
pub use crate::protocol::ProofData;
pub use crate::prover::{Prover, ProverPullConfig};

// Re-export prover types so downstream crates (e.g. proof_coordinator) can import from
// ethrex_prover without depending on ethrex_common directly.
pub use ethrex_common::types::prover::{ProofBytes, ProofFormat, ProverOutput, ProverType};

#[cfg(feature = "sp1")]
pub use crate::backend::Sp1Backend;

#[cfg(feature = "risc0")]
pub use crate::backend::Risc0Backend;

#[cfg(feature = "zisk")]
pub use crate::backend::ZiskBackend;

#[cfg(feature = "openvm")]
pub use crate::backend::OpenVmBackend;
