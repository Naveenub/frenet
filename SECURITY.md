# Security
- Crypto: Noise (XX) and Ed25519 via libp2p / `@libp2p/crypto`. No custom algorithms.
- Private keys never leave `<data>/identity.key`. Back it up; losing it loses the identity (no recovery yet).
- This is unaudited pre-release software. Do not rely on it for high-risk use.
- Report vulnerabilities privately to the maintainers before disclosure.
