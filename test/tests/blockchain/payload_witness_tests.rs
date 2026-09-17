//! Payload witnesses come from the original execution, without importing the candidate.
use std::{collections::BTreeMap, sync::Arc};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain, BlockchainOptions,
    payload::{BuildPayloadArgs, PayloadBuildResult, PayloadOrTask, create_payload},
    payload_witness::{PayloadWitness, PayloadWitnessMode},
};
use ethrex_common::{
    Address, H256, U256,
    types::{
        Block, EIP1559Transaction, ELASTICITY_MULTIPLIER, Genesis, GenesisAccount,
        MempoolTransaction, Transaction, TxKind, Withdrawal,
        block_execution_witness::{ExtWitness, RpcExecutionWitness},
    },
};
use ethrex_crypto::NativeCrypto;
use ethrex_guest_program::common::execute_blocks;
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_rlp::{decode::RLPDecode, encode::RLPEncode};
use ethrex_rpc::{
    engine::{
        CAPABILITIES,
        payload::{GetPayloadV6Request, GetPayloadWithWitnessV6Request},
    },
    rpc::{RpcHandler, map_engine_requests},
    test_utils::{TestContext, default_context_with_storage},
    utils::{RpcErrorMetadata, RpcRequest},
};
use ethrex_storage::{EngineType, Store};
use ethrex_vm::Evm;
use secp256k1::SecretKey;
use serde_json::json;

fn signer() -> Signer {
    Signer::Local(LocalSigner::new(SecretKey::from_slice(&[1; 32]).unwrap()))
}

async fn setup(mode: PayloadWitnessMode) -> (Arc<Blockchain>, Block) {
    let mut genesis: Genesis = serde_json::from_slice(include_bytes!(
        "../../../fixtures/genesis/l1-bal-content.json"
    ))
    .unwrap();
    genesis.alloc.insert(
        signer().address(),
        GenesisAccount {
            balance: U256::from(10).pow(U256::from(24)),
            code: Bytes::new(),
            storage: BTreeMap::new(),
            nonce: 0,
        },
    );
    // Read-only storage, deletion + update, reverted reads, and BLOCKHASH.
    for (id, code) in [
        (0x9001, "6000545000"),
        (0x9002, "6000600055600960015500"),
        (0x9003, "6000545060006000fd"),
        (0x9004, "6000405000"),
    ] {
        genesis.alloc.insert(
            Address::from_low_u64_be(id),
            GenesisAccount {
                code: Bytes::from(hex::decode(code).unwrap()),
                storage: BTreeMap::from([(U256::zero(), U256::from(7))]),
                balance: U256::zero(),
                nonce: 0,
            },
        );
    }
    // Queue one EIP-7002 request in the parent state so post-transaction
    // system calls produce a non-empty execution request as well.
    let queue = &mut genesis
        .alloc
        .get_mut(&ethrex_vm::system_contracts::WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS.address)
        .unwrap()
        .storage;
    queue.extend([
        (U256::from(1), U256::from(1)),      // requests this block
        (U256::from(3), U256::from(1)),      // queue tail (head is zero)
        (U256::from(4), U256::from(0x9006)), // source address
        (U256::from(5), U256::from(7)),      // first 32 bytes of validator pubkey
        (U256::from(6), (U256::from(8) << 128) + U256::from(1)),
    ]);
    let mut store = Store::new("", EngineType::InMemory).unwrap();
    store.add_initial_state(genesis).await.unwrap();
    let parent = store.get_block_header(0).unwrap().unwrap();
    let template = create_payload(
        &BuildPayloadArgs {
            parent: parent.hash(),
            timestamp: parent.timestamp + 12,
            fee_recipient: Address::from_low_u64_be(0x9005),
            random: H256::zero(),
            withdrawals: Some(vec![Withdrawal {
                index: 0,
                validator_index: 1,
                address: Address::from_low_u64_be(0x9006),
                amount: 5,
            }]),
            beacon_root: Some(H256::from_low_u64_be(1)),
            slot_number: Some(1),
            version: 4,
            elasticity_multiplier: ELASTICITY_MULTIPLIER,
            gas_ceil: parent.gas_limit,
        },
        &store,
        Bytes::new(),
    )
    .unwrap();
    let blockchain = Arc::new(Blockchain::new(
        store,
        BlockchainOptions {
            builder_witness_mode: mode,
            ..Default::default()
        },
    ));
    (blockchain, template)
}

async fn transaction(blockchain: &Blockchain, nonce: u64, recipient: u64) -> Transaction {
    let mut tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id: blockchain.store().get_chain_config().chain_id,
        nonce,
        max_fee_per_gas: 10_000_000_000,
        max_priority_fee_per_gas: 10,
        gas_limit: 200_000,
        to: TxKind::Call(Address::from_low_u64_be(recipient)),
        ..Default::default()
    });
    tx.sign_inplace(&signer()).await.unwrap();
    tx
}

fn replay(blockchain: &Blockchain, result: &PayloadBuildResult, encoded: &Bytes) {
    let ext = ExtWitness::decode(encoded).unwrap();
    assert!(!ext.headers.is_empty());
    let rpc = RpcExecutionWitness {
        state: ext.state,
        codes: ext.codes,
        keys: ext.keys,
        headers: ext
            .headers
            .iter()
            .map(|h| Bytes::from(h.encode_to_vec()))
            .collect(),
    };
    let witness = rpc
        .into_execution_witness(
            blockchain.store().get_chain_config(),
            result.payload.header.number,
            &ext.headers,
            &NativeCrypto,
        )
        .unwrap();
    execute_blocks(
        std::slice::from_ref(&result.payload),
        witness,
        ELASTICITY_MULTIPLIER,
        |db, _| Ok(Evm::new_for_l1(db.clone(), Arc::new(NativeCrypto))),
        Arc::new(NativeCrypto),
    )
    .expect("candidate must validate with witness state alone");
}

async fn assert_not_imported(blockchain: &Blockchain, result: &PayloadBuildResult) {
    assert!(
        blockchain
            .store()
            .get_block_header_by_hash(result.payload.hash())
            .unwrap()
            .is_none()
    );
    assert_eq!(blockchain.store().get_latest_block_number().unwrap(), 0);
}

async fn cache(blockchain: &Blockchain, id: u64, result: PayloadBuildResult) {
    blockchain.payloads.lock().await.push((
        id,
        Arc::new(tokio::sync::Mutex::new(PayloadOrTask::Payload(Box::new(
            result,
        )))),
    ));
}

async fn rpc_context(blockchain: &Arc<Blockchain>) -> TestContext {
    let mut ctx = default_context_with_storage(blockchain.store().clone()).await;
    ctx.blockchain = blockchain.clone();
    ctx
}

#[tokio::test]
async fn payload_witness_modes_replay_empty_and_full_candidates() {
    for mode in [PayloadWitnessMode::Eager, PayloadWitnessMode::OnDemand] {
        let (blockchain, template) = setup(mode).await;
        let empty = blockchain.build_payload(template.clone()).unwrap();
        assert!(empty.payload.body.transactions.is_empty());
        assert!(
            empty.requests.iter().any(|request| !request.is_empty()),
            "fixture must produce an execution request"
        );
        match mode {
            PayloadWitnessMode::Eager => {
                assert!(matches!(empty.witness, PayloadWitness::Ready(Ok(_))))
            }
            PayloadWitnessMode::OnDemand => {
                assert!(matches!(empty.witness, PayloadWitness::Pending(_)))
            }
            _ => unreachable!(),
        }
        let witness = empty.witness.get(blockchain.clone()).await.unwrap();
        replay(&blockchain, &empty, &witness);
        assert_not_imported(&blockchain, &empty).await;

        for (nonce, recipient) in [0x9001, 0x9002, 0x9003, 0x9004].into_iter().enumerate() {
            blockchain
                .add_transaction_to_pool(transaction(&blockchain, nonce as u64, recipient).await)
                .await
                .unwrap();
        }
        // This transaction passes admission but becomes unaffordable after the
        // earlier transactions consume gas. The builder attempts and excludes it.
        let mut excluded = transaction(&blockchain, 4, 0x9001).await;
        if let Transaction::EIP1559Transaction(ref mut tx) = excluded {
            tx.value = U256::from(10).pow(U256::from(24)) - U256::from(200_000u64 * 10_000_000_000);
        }
        excluded.sign_inplace(&signer()).await.unwrap();
        // Use direct insertion so pool admission policy cannot hide the builder case.
        blockchain
            .mempool
            .add_transaction(
                excluded.hash(&NativeCrypto),
                signer().address(),
                MempoolTransaction::new(excluded, signer().address()),
                None,
                None,
            )
            .unwrap();

        let full = blockchain.build_payload(template).unwrap();
        assert_eq!(full.payload.body.transactions.len(), 4);
        assert!(!full.receipts[2].succeeded);
        let witness = full.witness.get(blockchain.clone()).await.unwrap();
        replay(&blockchain, &full, &witness);
        let repeated = full.witness.get(blockchain.clone()).await.unwrap();
        assert_eq!(witness, repeated);
        assert_eq!(
            witness.as_ptr(),
            repeated.as_ptr(),
            "encoded result is shared"
        );
        assert_not_imported(&blockchain, &full).await;
    }
}

#[tokio::test]
async fn payload_witness_rpc_retrieval_orders_and_concurrent_requests() {
    for mode in [PayloadWitnessMode::Eager, PayloadWitnessMode::OnDemand] {
        for witness_first in [false, true] {
            let (blockchain, template) = setup(mode).await;
            blockchain
                .clone()
                .initiate_payload_build(template.clone(), 42)
                .await;
            let ctx = rpc_context(&blockchain).await;
            let ordinary = GetPayloadV6Request { payload_id: 42 };
            let with_witness = GetPayloadWithWitnessV6Request { payload_id: 42 };
            let (plain, extended) = if witness_first {
                let extended = with_witness.handle(ctx.clone()).await.unwrap();
                (ordinary.handle(ctx.clone()).await.unwrap(), extended)
            } else {
                let plain = ordinary.handle(ctx.clone()).await.unwrap();
                (plain, with_witness.handle(ctx.clone()).await.unwrap())
            };
            assert!(plain.get("witness").is_none());
            let mut stripped = extended.clone();
            assert!(
                stripped
                    .as_object_mut()
                    .unwrap()
                    .remove("witness")
                    .unwrap()
                    .is_string()
            );
            assert_eq!(plain, stripped);
            let (a, b, c) = tokio::join!(
                ordinary.handle(ctx.clone()),
                with_witness.handle(ctx.clone()),
                with_witness.handle(ctx.clone()),
            );
            assert_eq!(a.unwrap(), plain);
            assert_eq!(b.unwrap(), extended);
            assert_eq!(c.unwrap(), extended);
            // Exercise simultaneous first retrievals, before an on-demand
            // witness exists, as well as the cached retrievals above.
            cache(&blockchain, 43, blockchain.build_payload(template).unwrap()).await;
            let first = GetPayloadWithWitnessV6Request { payload_id: 43 };
            let normal = GetPayloadV6Request { payload_id: 43 };
            let (a, b, c) = tokio::join!(
                first.handle(ctx.clone()),
                first.handle(ctx.clone()),
                normal.handle(ctx.clone())
            );
            assert_eq!(a.unwrap(), b.unwrap());
            assert_eq!(c.unwrap(), plain);
            let result = blockchain.get_payload(42).await.unwrap();
            let encoded = Bytes::from(
                hex::decode(
                    extended["witness"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                )
                .unwrap(),
            );
            replay(&blockchain, &result, &encoded);
            assert_not_imported(&blockchain, &result).await;
        }
    }
}

#[tokio::test]
async fn payload_witness_rpc_errors_preserve_ordinary_payload() {
    assert!(CAPABILITIES.contains(&"engine_getPayloadWithWitnessV6"));
    let (blockchain, template) = setup(PayloadWitnessMode::Off).await;
    let result = blockchain.build_payload(template).unwrap();
    cache(&blockchain, 1, result.clone()).await;
    let mut ctx = rpc_context(&blockchain).await;
    let req = RpcRequest {
        method: "engine_getPayloadWithWitnessV6".into(),
        params: Some(vec![json!("0x0000000000000001")]),
        ..Default::default()
    };
    let err = map_engine_requests(&req, ctx.clone()).await.unwrap_err();
    assert_eq!(RpcErrorMetadata::from(err).code, -32603);
    assert!(
        GetPayloadV6Request { payload_id: 1 }
            .handle(ctx.clone())
            .await
            .is_ok()
    );
    let err = GetPayloadWithWitnessV6Request { payload_id: 999 }
        .handle(ctx.clone())
        .await
        .unwrap_err();
    assert_eq!(RpcErrorMetadata::from(err).code, -38001);
    let mut failed = result.clone();
    failed.witness = PayloadWitness::Ready(Err("parent state unavailable".into()));
    cache(&blockchain, 2, failed).await;
    for _ in 0..2 {
        let err = GetPayloadWithWitnessV6Request { payload_id: 2 }
            .handle(ctx.clone())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("parent state unavailable"));
        assert!(
            GetPayloadV6Request { payload_id: 2 }
                .handle(ctx.clone())
                .await
                .is_ok()
        );
    }
    let mut old = result;
    old.payload.header.timestamp = 0;
    let mut store = blockchain.store().clone();
    let mut config = store.get_chain_config();
    config.amsterdam_time = Some(1);
    store.set_chain_config(&config).await.unwrap();
    ctx.storage = store;
    cache(&blockchain, 3, old).await;
    let err = GetPayloadWithWitnessV6Request { payload_id: 3 }
        .handle(ctx.clone())
        .await
        .unwrap_err();
    assert_eq!(RpcErrorMetadata::from(err).code, -38005);
    assert!(GetPayloadWithWitnessV6Request::parse(&Some(vec![])).is_err());
}

#[tokio::test]
async fn payload_witness_build_loop_keeps_witness_with_selected_candidate() {
    for initially_empty in [true, false] {
        let (blockchain, template) = setup(PayloadWitnessMode::OnDemand).await;
        if !initially_empty {
            blockchain
                .add_transaction_to_pool(transaction(&blockchain, 0, 0x9001).await)
                .await
                .unwrap();
        }
        let cancel = tokio_util::sync::CancellationToken::new();
        let mut build = std::pin::pin!(
            blockchain
                .clone()
                .build_payload_loop(template, cancel.clone())
        );
        // On-demand mode executes the initial candidate synchronously, then waits
        // for transactions. This forces the cancellation race without sleeps.
        std::future::poll_fn(|cx| {
            assert!(build.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let next_nonce = if initially_empty { 0 } else { 1 };
        blockchain
            .add_transaction_to_pool(transaction(&blockchain, next_nonce, 0x9002).await)
            .await
            .unwrap();
        cancel.cancel();
        let selected = build.await.unwrap();
        assert_eq!(selected.payload.body.transactions.len(), 1);
        let recipient = if initially_empty { 0x9002 } else { 0x9001 };
        assert_eq!(
            selected.payload.body.transactions[0].to(),
            TxKind::Call(Address::from_low_u64_be(recipient))
        );
        let encoded = selected.witness.get(blockchain.clone()).await.unwrap();
        replay(&blockchain, &selected, &encoded);
        assert_not_imported(&blockchain, &selected).await;
    }
}

#[tokio::test]
async fn payload_witness_eviction_releases_pending_inputs() {
    let (blockchain, template) = setup(PayloadWitnessMode::OnDemand).await;
    let result = blockchain.build_payload(template).unwrap();
    let weak = match &result.witness {
        PayloadWitness::Pending(inputs) => Arc::downgrade(inputs),
        _ => panic!("expected deferred witness"),
    };
    cache(&blockchain, 1, result).await;
    let held = blockchain.get_payload(1).await.unwrap();
    blockchain.payloads.lock().await.clear();
    assert!(
        weak.upgrade().is_some(),
        "active retrieval retains its own inputs"
    );
    drop(held);
    assert!(
        weak.upgrade().is_none(),
        "evicted candidate releases its inputs"
    );
}
