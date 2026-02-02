🔐 idmap-prism

### Privacy-Preserving Proof Engine for Solana

IdMap Prism is a **privacy-preserving proof engine** for Solana that lets users prove statements like "my balance is ≥ X", "I interacted with program Y", or "I hold token Z" without revealing their actual balances or full transaction history. It combines threshold MPC, ZK proofs, and Solana Token-2022 confidential transfers into a single, auditable system.

Powered by CGGMP21 DKG, Ed25519 Threshold Signatures, and Arkworks ZK Circuits

[Rust](https://www.rust-lang.org/) [Solana](https://solana.com/) [MPC](https://en.wikipedia.org/wiki/Secure_multi-party_computation) [ZK-Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof) [License](https://mit-license.org/)

📖 Overview
-----------

This system acts as a **privacy-preserving auditor** for Confidential Token-2022 accounts, enabling secure identity attestations without raw data exposure.

**Key Features:**

*   **Threshold MPC**: 2-of-3 CGGMP21 DKG with no trusted dealer
*   **Confidential Predicates**: Prove balances and holdings without revealing amounts
*   **Hybrid Proof Modes**: MPC-attested (low-latency) and ZK-trustless (blind)
*   **Token-2022 Native**: Built-in support for confidential transfer extensions
*   **Entropy Budgeting**: Prevents data triangulation via leakage tracking
*   **Audit-Ready**: Formally verifiable circuits and UC-secure protocols


🏗️ Architecture & Workflow
---------------------------

### 🧩 System Components

| Component | Description |
|-----------|-------------|
| **`idmap-core`** | Cryptographic core (DKG, threshold signing, R1CS circuits) |
| **`idmap-orchestrator`** | Logic layer for MPC session mesh and predicate orchestration |
| **`idmap-gateway`** | Axum-based REST/WS interface for wallets and dApps |
| **SPL Token-2022** | Integration with Solana confidential transfer extensions |

### 🔒 Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Threshold Privacy** | Private keys and raw balances never exist in complete form on any single node. |
| **Inference Defense** | Global entropy budgeting ensures users can't be deanonymized via multiple requests. |
| **Resilient by Design** | 2-of-3 committee allows one node failure without service interruption. |
| **Stateless Proving** | Horizontally scalable gateway and prover nodes for high throughput. |

🛠️ Tech Stack
--------------

| Crate | Purpose |
|-------|---------|
| **givre** | CGGMP21 DKG + Ed25519 threshold signing |
| **swanky** | Garbled circuits for secure MPC comparisons |
| **arkworks** | R1CS circuits and Groth16 proving (BLS12-381) |
| **axum** | High-performance async API gateway |
| **tokio** | Foundation for the async runtime |

### 🚀 Performance Targets

*   **MPC-Attested Mode**: < 500ms (P95)
*   **ZK-Trustless Mode**: < 5s (P95)
*   **API Throughput**: 1,000+ req/s per instance

---

**Built with ❤️ for a private and trustless Solana ecosystem.**
