# TODOs

## List

### NOTE: Investigate why testing is failing here

- [X] None (Doesn't need to be secure but also needs to not introduce any vulnerabilities)
- [X] Must take <3s
- [X] Completed All Objectives

## Attest (Henry + David)

- [ ] Attestion PIN - 6 byte integer
- [ ] Store Attestation PIN as SHA256 hash of PIN with however many iterations takes 2s to limit brute force
- [ ] Wrap Attestation Data Key with 0x0000 ++ PIN as IV and SHA256 hash of PIN with however many iterations minus 1 as key
- [ ] Store Attestation Data AES-128-CTR mode encrypted with random IV and SHA256 has of PIN with however many iterations minus 1 as key
- [ ] Must take <3s
- [ ] Completed All Objectives

## Replace (Ezequiel + Cam)

- [X] Replacement token - 16 byte integer
- [X] Store replacement token as SHA256 hash
- [X] Store predefined ECC public key and generate a random number [RNG Example](https://github.com/Analog-Devices-MSDK/msdk/tree/e20c2cfe54f3d8880d29c11390700840e7e7ba27/Examples/MAX78000/TRNG)
- [X] Ask for component to sign random number
- [X] Verify signature
- [X] Completed All Objectives

## Boot (Tyler)

- [ ] Store predefined ECC public key 1 on AP and generate a random number [RNG Example](https://github.com/Analog-Devices-MSDK/msdk/tree/e20c2cfe54f3d8880d29c11390700840e7e7ba27/Examples/MAX78000/TRNG)
- [ ] Ask for Component1 to sign random number
- [ ] Verify signature
- [ ] Store predefined ECC public key 2 on Component1
- [ ] Ask for AP to sign random number
- [ ] Verify signature
- [ ] Store predefined ECC public key 3 on Component2
- [ ] Ask for AP to sign random number
- [ ] Verify signature
- [ ] Store predefined ECC public key 4 on AP
- [ ] Ask for Component2 to sign random number
- [ ] Verify signature
- [ ] If any of the above do not check out the integrity has been compromised
- [ ] Completed All Objectives

## Secure Send & Receive (Andrew)

- [X] ECDHE Encryption Scheme
- [X] Encrypt all packets with AES-128-CTR mode
- [X] Derive Private Key randomly
- [X] SHA256 ECDH Shared Secret
- [X] First 16 bytes of hash as AES key, Next 8 as IV
- [X] Negotiate HMAC key over encrypted channel
- [X] Append an HMAC to end of all other packets before encrypting
- [X] Completed All Objectives
