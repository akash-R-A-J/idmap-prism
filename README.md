# IdMap Prism

IdMap Prism is a **privacy-preserving proof engine** for Solana that lets users prove statements like "my balance is ≥ X", "I interacted with program Y", or "I hold token Z" without revealing their actual balances or full transaction history.
It does this by combining threshold MPC, ZK proofs, and Solana Token‑2022 confidential transfers into a single, auditable system.

---

## What IdMap Prism Does

IdMap Prism generates **Prism Proofs** — cryptographically signed attestations over confidential Solana state (Token‑2022 balances, program interactions, token holdings) that can be verified by dApps, exchanges, DAOs or regulators.

Core properties:

- No raw balances or full history ever leave the user's wallet; only predicates do.
- Keys are held via threshold MPC; no single node can decrypt or sign alone.
- Proofs can be produced in two modes:
  - **MPC‑attested (fast)** – low‑latency proofs with a trusted MPC committee.
  - **ZK‑trustless (blind)** – client‑side ZK proving with on‑chain verifiable proofs.

Typical use cases:

- Proof‑of‑funds for OTC/RWA flows
- KYC/AML‑friendly gating without full doxxing
- DAO and governance voting power proofs
- Token‑gated access and airdrop eligibility

---

## High‑Level Architecture

The system is split into three main Rust services, plus Solana Token‑2022 integration:

- **`idmap-core`** – cryptographic engine
  - N‑of‑M threshold DKG & signing (CGGMP21, Ed25519).
  - MPC comparison via `givre` + `swanky` and ZK circuits via `arkworks` (Groth16 on BLS12‑381).
  - Confidential balance predicates, entropy budgeting, proof ID computation.

- **`idmap-orchestrator`** – coordination & business logic
  - Drives MPC sessions across the node mesh, manages predicate workflows, recovery, retries and circuit breakers.
  - Tracks proof lifecycle, session checkpoints, and resilience policies.

- **`idmap-gateway`** – public API gateway
  - Axum‑based HTTP/WebSocket API used by wallets, dApps and backends.
  - Handles auth, rate limiting, health checks and exposes proof request/verification endpoints.

- **Solana / Token‑2022 integration**
  - Whitelist registry for approved Token‑2022 mints (SOL, USDC, USDT first‑class).
  - ConfidentialTransfer auditor key split across MPC nodes; balances decrypted only via threshold ElGamal, never on a single machine.

At a glance, IdMap Prism acts as a **privacy‑preserving auditor** for Confidential Token‑2022 accounts, sitting between user wallets, Solana RPC, and verifiers.

---

## Security Model

IdMap Prism is designed around explicit, measurable security parameters:

### Cryptographic guarantees

- **128‑bit security** via Ed25519 and BLS12‑381.
- **Threshold security**: configurable N‑of‑M, default **2‑of‑3** using CGGMP21, with no trusted dealer.
- **Key material** is never reconstructed; all operations (decrypt, sign, compare) are performed over shares only.
- **Share verification** uses VSS commitments during DKG.
- **Signatures**: 64‑byte Ed25519 signatures, Solana‑native and on‑chain verifiable.

### Operational guarantees

- Honest‑majority assumption: at least 2 of 3 MPC nodes must be honest for the default deployment.
- mTLS between all MPC nodes; no plaintext intra‑cluster traffic.
- Entropy budgeting with refusal if a user's remaining privacy budget drops below 128 bits.
- Proofs are uniquely bound using `proof_id = H(predicate || params || expiry)` to prevent replay.

---

## Performance Targets

The project sets explicit latency and throughput goals for production deployments:

### Latency targets

- **MPC‑attested mode**:
  - End‑to‑end target < 500 ms (P95 ≤ 400 ms).
- **ZK‑trustless mode**:
  - End‑to‑end target < 5 s (P95 ≤ 3.5 s).

Selected micro‑targets:

- MPC simple predicate: P95 ≤ 150–300 ms.
- Threshold signature: P95 ≤ 100 ms.
- ZK proof generation: P95 ≤ 2.5–3.5 s with verification < 20 ms.

### Throughput targets

- API gateway: ~1,000 req/s per instance (stateless, horizontally scaled).
- MPC cluster: ~100 proofs/s via parallel MPC sessions.
- ZK prover: ~10 proofs/s per core with future GPU offload.

---

## Fault Tolerance & Resilience

IdMap Prism treats availability and graceful degradation as first‑class features.

### Availability & recovery

- Overall system target: **99.9%** availability with 2‑of‑3 threshold MPC.
- MPC cluster target: **99.95%** (tolerates 1 node failing completely).
- RTO < 30 seconds; RPO = 0 via WAL and synchronous commits on PostgreSQL.

### Failure scenarios

- 1 MPC node down → no impact on correctness; node is auto‑excluded from quorum.
- Redis / PostgreSQL primary down → brief pause while Sentinel / failover promotes a replica.
- Network partition → session timeout and automatic retry with a fresh session.

### Circuit breakers, retries, timeouts

Configurable YAML‑driven resilience layer with:

- Circuit breaker thresholds (failures before open, successes to close).
- Exponential backoff retry with jitter for transient failures.
- Operation‑specific timeouts for TCP, DKG, signing, RPC and ZK proving.

---

## Implementation Roadmap

The repository is being built in structured phases, from core MPC to full ZK‑trustless mode.

### Phase 1 – Core infra & N‑of‑M MPC (2–3 weeks)

- Dynamic threshold DKG with runtime mesh discovery.
- SQLx‑backed persistence for key shares.
- OpenTelemetry logging and tracing.

**Success**: 3‑node DKG with any 2 nodes able to produce valid signatures.

### Phase 2 – SDRF + predicate engine (2 weeks)

- SDRF parser and validation.
- Predicates: `balance_threshold`, `program_interaction`, `token_holding`.
- Entropy tracker and policy enforcement.

### Phase 3 – Token‑2022 integration (2–3 weeks)

- Auditor key DKG and threshold ElGamal decrypt.
- Mint registry and whitelist.
- Confidential Token‑2022 RPC integration.

### Phase 4 – Secure comparison + ZK trustless (3–4 weeks)

- Secure comparison via `swanky`.
- Arkworks R1CS circuits and Groth16 prover.
- On‑chain verifiable proofs.

### Phase 5 – API gateway + resilience (2 weeks)

- Axum REST/WebSocket gateway.
- Rate limiting and circuit breakers.
- Kubernetes‑ready health probes.

### Phase 6 – Testing & hardening (2–3 weeks)

- 80%+ unit test coverage.
- E2E and chaos test suites.
- Load testing for 100+ concurrent proofs.

**Total MVP timeline**: ~14–18 weeks.

---

## Long‑Term Vision

Beyond the MVP, IdMap Prism has a 36‑month roadmap to evolve from "default utility" to "cryptographic inevitability".

### Security enhancements

- Proactive resharing to shrink key compromise windows to ~7 days.
- Optional TEEs (SGX/TDX/Nitro) for hardware‑backed isolation.
- Threshold ECDSA to extend beyond Solana.

### Performance optimizations

- GPU/FPGAs for 5–10× faster ZK proving.
- Beaver triple pre‑computation and proof batching.
- Async proof queues and proof caching.

### Developer experience

- Predicate DSL (no Rust required).
- SDKs (TypeScript, Python).
- WASM client SDK for browser verification.

The philosophy: **win utility first** (become the default Solana identity/proof rail), then progressively harden until both math and infrastructure are unbreakable.

---

## Status

- **Version**: 1.0 technical spec
- **Status**: Actively under implementation
- **Technical Spec**: [DeepWiki Documentation](https://deepwiki.com/akash-R-A-J/idmap-prism)

---

## Contributing

IdMap Prism is open to community contributions. If you're interested in:

- Cryptography and MPC protocol implementation
- Solana / Token‑2022 integrations
- ZK circuit design
- Production deployment and resilience

Feel free to open an issue or pull request. For major changes, please discuss in an issue first.

---

## License

MIT (or your preferred license)

---

## Contact

- GitHub: [@akash-R-A-J](https://github.com/akash-R-A-J)
- X/Twitter: [@AKASH_Ra_aj](https://twitter.com/AKASH_Ra_aj)
