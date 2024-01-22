# TODOs

- Encrypt I2C Communication
  - ECDHE Encryption Scheme
  - Encrypt all packets with AES-128-CTR mode
  - Derive Private Key from RNG (does the board have an RNG?)
  - SHA256 of ECDH Shared Secret
  - First 16 bytes of hash as AES key, Next 8 as IV
  - Append a hard-coded? HMAC to end of packet
- Hash Replacement Token
  - Stored as SHA256 hash