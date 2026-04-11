#[cfg(feature = "eip-8025")]
mod chunked;
mod error;
mod execution;

#[cfg(feature = "eip-8025")]
pub(crate) use chunked::prepare_chunked_merge_context;
#[cfg(feature = "eip-8025")]
pub use chunked::{checkpoint_system_phase, decode_header_bal};
pub use error::ExecutionError;
pub use execution::{BatchExecutionResult, execute_blocks};
