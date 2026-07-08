# Contributing to the Consenti Agreement Protocol

Thank you for your interest in contributing. This protocol aims to become open infrastructure for verifiable terms acceptance in agentic commerce. Contributions that make the protocol more robust, interoperable, and widely adopted are welcome.

## What We're Looking For

**High-priority contributions:**
- Anchor provider implementations (EVM, Bitcoin, Solana, RFC 3161 TSA)
- SDK ports (Python, Go, Rust)
- Security reviews and vulnerability reports
- Real-world integration feedback (what broke when you tried to implement this?)
- Transport binding specs (A2A, additional MCP tooling, DNS TXT)

**Also welcome:**
- Documentation improvements
- Test coverage
- Example acceptance records from different use cases
- Tooling (CLI verifier, dashboard components)

## How to Contribute

### Bug Reports & Feature Requests

Open a GitHub Issue. For security vulnerabilities, email security@consenti.ai instead.

### Code Contributions

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/evm-anchor-provider`)
3. Write tests for new functionality
4. Ensure all tests pass (`npm test`)
5. Submit a PR with a clear description of what and why

### Protocol-Level Changes (RFCs)

Changes to the schema, discovery spec, or privacy architecture follow the RFC process described in [GOVERNANCE.md](GOVERNANCE.md). To propose a change:

1. Open an Issue titled `RFC: [Your Proposal]`
2. Describe the problem, the proposed change, and the tradeoffs
3. The maintainers will label it for discussion
4. After community feedback, the BDFL decides whether to accept, modify, or defer

## Code Style

- TypeScript with strict mode
- No external runtime dependencies (the verifier must work standalone)
- RFC 8785 canonicalization must remain deterministic — do not add non-deterministic operations to the hash path

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
