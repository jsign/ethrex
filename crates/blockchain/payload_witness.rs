//! Witness assembly for a locally built candidate; never executes or imports a block.
use std::sync::{Arc, Mutex};

use ethrex_common::{
    Bytes,
    types::{AccountUpdate, Block, BlockHeader, block_execution_witness::RpcExecutionWitness},
};
use ethrex_vm::backends::levm::db::ExecutionAccesses;
use tokio::sync::watch;

use crate::{Blockchain, error::ChainError};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PayloadWitnessMode {
    #[default]
    Off,
    Eager,
    OnDemand,
}

impl std::str::FromStr for PayloadWitnessMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "eager" => Ok(Self::Eager),
            "on-demand" => Ok(Self::OnDemand),
            _ => Err("expected off, eager, or on-demand".into()),
        }
    }
}

/// All inputs belong to one finalized candidate and its original parent.
#[derive(Debug)]
pub(crate) struct WitnessInputs {
    pub block: Block,
    pub parent: BlockHeader,
    pub account_updates: Vec<AccountUpdate>,
    pub accesses: ExecutionAccesses,
}

type WitnessResult = Result<Bytes, String>;

impl WitnessInputs {
    pub(crate) fn assemble(self, blockchain: &Blockchain) -> WitnessResult {
        let witness = blockchain
            .generate_witness_from_account_updates(
                self.account_updates,
                &self.block,
                self.parent,
                &self.accesses,
            )
            .map_err(|err| err.to_string())?;
        RpcExecutionWitness::try_from(witness)
            .map_err(|err| err.to_string())?
            .encode_engine()
            .map_err(|err| err.to_string())
    }
}

/// Clones share both pending inputs and the encoded result. Bytes clones share
/// their allocation; pending inputs are moved into the worker exactly once.
#[derive(Debug, Clone, Default)]
pub enum PayloadWitness {
    #[default]
    Disabled,
    Ready(WitnessResult),
    Pending(Arc<PendingWitness>),
}

#[derive(Debug)]
pub struct PendingWitness {
    inputs: Mutex<Option<WitnessInputs>>,
    result: watch::Sender<Option<WitnessResult>>,
}

impl PayloadWitness {
    pub(crate) fn pending(inputs: WitnessInputs) -> Self {
        let (result, _) = watch::channel(None);
        Self::Pending(Arc::new(PendingWitness {
            inputs: Mutex::new(Some(inputs)),
            result,
        }))
    }

    pub async fn get(&self, blockchain: Arc<Blockchain>) -> Result<Bytes, ChainError> {
        let result = match self {
            Self::Disabled => {
                return Err(ChainError::WitnessGeneration(
                    "payload witness recording is disabled; enable --builder.witness-mode".into(),
                ));
            }
            Self::Ready(result) => result.clone(),
            Self::Pending(pending) => {
                let mut receiver = pending.result.subscribe();
                let inputs = pending
                    .inputs
                    .lock()
                    .map_err(|_| {
                        ChainError::WitnessGeneration("Witness inputs lock poisoned".into())
                    })?
                    .take();
                if let Some(inputs) = inputs {
                    let pending = pending.clone();
                    // Ownership passes to an independent task before the first await.
                    // A disconnected RPC caller cannot cancel assembly or lose its result.
                    tokio::spawn(async move {
                        let result =
                            tokio::task::spawn_blocking(move || inputs.assemble(&blockchain))
                                .await
                                .unwrap_or_else(|err| Err(format!("Witness worker failed: {err}")));
                        pending.result.send_replace(Some(result));
                    });
                }
                loop {
                    if let Some(result) = receiver.borrow_and_update().clone() {
                        break result;
                    }
                    receiver.changed().await.map_err(|_| {
                        ChainError::WitnessGeneration(
                            "Witness worker closed without a result".into(),
                        )
                    })?;
                }
            }
        };
        result.map_err(ChainError::WitnessGeneration)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ethrex_storage::{EngineType, Store};
    use std::task::Poll;

    fn missing_parent_inputs() -> WitnessInputs {
        let parent = BlockHeader {
            timestamp: 42,
            ..Default::default()
        };
        let mut block = Block::default();
        block.header.number = 1;
        block.header.parent_hash = parent.hash();
        WitnessInputs {
            block,
            parent,
            account_updates: Vec::new(),
            accesses: ExecutionAccesses::default(),
        }
    }

    fn pending() -> PayloadWitness {
        PayloadWitness::pending(missing_parent_inputs())
    }

    #[tokio::test]
    async fn cancelled_witness_request_keeps_worker_and_caches_failure() {
        let blockchain = Arc::new(Blockchain::default_with_store(
            Store::new("", EngineType::InMemory).unwrap(),
        ));
        let witness = pending();
        let PayloadWitness::Pending(state) = &witness else {
            unreachable!()
        };
        assert!(state.inputs.lock().unwrap().is_some());
        assert!(state.result.borrow().is_none(), "assembly is deferred");
        {
            let mut future = std::pin::pin!(witness.get(blockchain.clone()));
            std::future::poll_fn(|cx| {
                assert!(future.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            // Drop the caller before the independently spawned worker runs.
        }
        assert!(
            state.inputs.lock().unwrap().is_none(),
            "inputs moved to exactly one worker"
        );
        let (a, b) = tokio::join!(
            witness.get(blockchain.clone()),
            witness.get(blockchain.clone())
        );
        let first = a.unwrap_err().to_string();
        assert_eq!(first, b.unwrap_err().to_string());
        assert!(state.result.borrow().as_ref().unwrap().is_err());
        assert_eq!(
            first,
            witness.get(blockchain).await.unwrap_err().to_string()
        );
    }

    #[test]
    fn eager_failure_remains_a_witness_result() {
        let blockchain =
            Blockchain::default_with_store(Store::new("", EngineType::InMemory).unwrap());
        let inputs = missing_parent_inputs();
        assert!(
            inputs.assemble(&blockchain).is_err(),
            "missing parent cannot produce a witness"
        );
    }
}
