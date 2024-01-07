# Go-Crypt (!!! WIP !!!)

This project is a comprehensive toolkit for developers who need to implement various cryptographic operations in their Go applications


## Crypto suite:
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
    - XChacha20-poly1305 Stream (utilized age code)
    - XOR
    - AES-GCM
    - "Insecure"
        - SecretBox
        - AES-CTR
        - AES-CBC
- Asymmetric
    - ECDSA
        - ed25519
        - ed448
    - ECDH
        - Curve25519
- Hash
    - Blake2b-256
    - Blake2b-384
    - Blake2b-512
    - SHA3-256
    - SHA3-384
    - SHA3-512
    - SHAKE-128 (planned)
    - SHAKE-256 (planned)
    - go_simhash (planned)
    - Argon2id
    - Scrypt (planed)
    - HKDF (planed)
- Compression
    - flate
    - gzip
    - zlib
    - zstd
    - brotli
    - huff0X1 (in progress)
    - huff0X4 (in progress)

- Aged 
    - Age encryption suite
    - Age header obfuscation v1

## Disclaimer

This project includes cryptographic operations that have not been independently audited. While every effort has been made to ensure the correctness and security of these operations, they are provided "as is". The author cannot guarantee their security and cannot be held responsible for any consequences arising from their use. If you use these package in your own projects, you do so at your own risk.

It is strongly recommended that you seek an independent security review if you plan to use them in a production environment.