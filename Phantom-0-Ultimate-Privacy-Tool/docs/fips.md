# Toward FIPS Alignment (Practical Guidance)

This project is shell-based; FIPS concerns primarily arise from crypto libs.
To pursue FIPS-aligned builds:

1. **Use a FIPS-enabled distro** (e.g., RHEL/UBI, Ubuntu Pro FIPS) for production.
2. **Prefer system crypto** rather than bundling: leverage OpenSSL or kernel
   primitives provided by the platform in FIPS mode.
3. **Configuration**: ensure `fips=1` boot flag (distro-specific) and verify
   `openssl fips` or provider status where applicable.
4. **Scope**: Keep Phantom‑0 free of custom cryptographic implementations.
5. **Documentation**: Provide operator guidance on FIPS deployment posture.

This repo ships no cryptographic modules of its own; it relies on the host OS.
