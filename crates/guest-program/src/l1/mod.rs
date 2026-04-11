#[cfg(feature = "eip-8025")]
mod chunk;
mod input;
#[cfg(feature = "eip-8025")]
mod merge;
mod output;
#[cfg(feature = "eip-8025")]
mod parallel;
mod program;

#[cfg(feature = "eip-8025")]
pub use chunk::{ChunkProgramInput, execution_program as chunk_execution_program};
pub use input::ProgramInput;
#[cfg(feature = "eip-8025")]
pub use input::{ProgramInputDecodeError, ProgramInputEncodeError};
#[cfg(feature = "eip-8025")]
pub use input::{decode_eip8025, encode_eip8025};
#[cfg(feature = "eip-8025")]
pub use merge::execution_program as merge_execution_program;
pub use output::ProgramOutput;
#[cfg(feature = "eip-8025")]
pub use parallel::{
    CanonicalChunkArtifact, CanonicalObservedAddress, CanonicalObservedStorageAccess,
    ChunkProgramOutput, ChunkRange, MergeProgramInput, TxExecutionSummary,
    build_receipts_from_summaries, chunk_commitment_hash, compute_block_gas_from_summaries,
    validate_chunk_coverage,
};
pub use program::execution_program;
#[cfg(feature = "eip-8025")]
pub use program::prepare_new_payload_request;
