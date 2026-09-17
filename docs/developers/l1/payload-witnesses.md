# Witnesses for locally built payloads

Use `--builder.witness-mode=off|eager|on-demand` (or
`ETHREX_BUILDER_WITNESS_MODE`) to control witness generation for L1 payload
building. The default is `off`.

Both enabled modes record state accesses during the original candidate execution.
Witness assembly collects the corresponding parent-state trie nodes, bytecodes,
and ancestor headers. It does not re-execute or import the candidate.

- `eager` assembles and encodes a witness for each completed candidate before
  replacing the previous candidate.
- `on-demand` retains each candidate's access records and assembles its witness
  when first requested.

This setting is independent of `--precompute-witnesses`, which generates and
stores witnesses during block import. It does not enable witnesses in the L2
sequencer.

## Retrieval

After starting a build with `engine_forkchoiceUpdated`, call the authenticated
ethrex extension `engine_getPayloadWithWitnessV6` with the returned payload ID:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "engine_getPayloadWithWitnessV6",
  "params": ["0x0000000000000001"]
}
```

The result contains all fields of `engine_getPayloadV6` plus a required `witness`
hex string. It uses the same opaque RLP `ExtWitness` encoding as
`engine_newPayloadWithWitnessV5`: `(headers, codes, state, keys)`. The method
applies the same fork checks as V6 and is advertised by
`engine_exchangeCapabilities`. It is an ethrex extension, not a standard Engine
API method.

Ordinary `engine_getPayload*` responses remain unchanged. In on-demand mode,
ordinary retrieval freezes the candidate without assembling its witness. A later
witness request returns the witness for that same candidate. Repeated and
concurrent requests share the encoded result; disconnecting a caller does not
cancel witness assembly.

A witness error leaves the execution payload available through ordinary
retrieval. Disabled recording, missing parent state, or assembly failure produces
an internal RPC error, never a successful response with a null witness. Unknown
payload IDs and unsupported forks retain their usual Engine API errors. Assembly
failures are cached for the candidate, and retrieval never falls back to replay.

Candidates and witnesses follow the existing in-memory payload-cache lifetime.
Parent state is not pinned for later retrieval, so delayed on-demand requests may
fail after that state becomes unavailable. Witnesses may contain extra accesses
from transactions the builder attempted but excluded; minimal witnesses are not
guaranteed.
