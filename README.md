# Go-Crypt (!!! WIP !!!)

High-level API binding to low-level crypto APIs in golang


Crypto suite:
- Generic
    - (Secure) Overwrite
    - (Secure) Delete
    - CSPRNG
    - CSPRNGHex
    - /dev/hwrng
    - Encoders
        - Base64
        - Base32
        - Hex
    - Key Wrappers
        - ed25519
            - PKIX
            - PKCS
- Symmetric
    - XChacha20-poly1305
    - XChacha20-poly1305 Stream (modified age code)
    - XOR
    - AES-GCM
- Asymmetric
    - ed25519
    - ed448 
    - x25519 (pending)
- Hash
    - Blake2b-256
    - Blake2b-384
    - Blake2b-512
    - SHA3-256
    - SHA3-384
    - SHA3-512
    - SHAKE-128 (pending)
    - SHAKE-256 (pending)
    - go_simhash (pending)
    - Argon2id
    - Scrypt (pending)
    - HKDF (pending) 
- Compression
    - flate
    - gzip
    - zlib
    - zstd
- Aged 
    - Age encryption suite
    - Age header obfuscation v1

