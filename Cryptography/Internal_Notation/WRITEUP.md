# Challenge Overview: Internal Notation

**Category:** Cryptography  
**Event:** L3m0nCTF 2025  
**Role:** Challenge Author

> 🛠️ **Author Note**  
> This challenge was authored by me for **L3m0nCTF 2025**.  
> The following explanation describes the **intended analysis path**.

## Intended Analysis Path
The challenge required identifying the cryptographic primitive in use,
correctly interpreting the provided parameters, and avoiding brute-force
approaches in favor of structural analysis.

## Problem

During analysis of a recovered transmission, investigators found an encrypted message accompanied by a short configuration note written in the operator’s internal shorthand.

The note was never meant to explain the device — only to record its state for someone already familiar with it.

Your task is to interpret the notation correctly, configure the cipher accordingly, and recover the original message.

Once recovered, submit the plaintext wrapped in the following format:

L3m0nCTF{RECOVERED_MESSAGE}

The recovered message contains only alphabetic characters.

Preserve word order exactly as recovered.

---

## Analysis Phase 1 — Cipher Classification

The ciphertext consists only of **uppercase alphabetic characters**, with:

- No digits
- No punctuation
- No letter ever encrypting to itself
- Repeated letters encrypting to different characters

These properties immediately rule out:

- Simple substitution ciphers
- Vigenère-style polyalphabetic ciphers

This behavior is characteristic of a **rotor-based polyalphabetic cipher**, specifically an **Enigma-style machine**.

## Analysis Phase 2 — Configuration Interpretation

The provided configuration file is:

```
5 | 2 | 4
C
2-5-14
11-5-25
∅
```

The note is clearly not explanatory, meaning it assumes prior knowledge of the machine’s format.

We interpret each line in order.

- **Line 1**: `5 | 2 | 4`

This matches the standard way rotor orders are written.

Interpreted as:

`Rotor V – Rotor II – Rotor IV`

These are valid rotor identifiers used in historical Enigma machines.

- **Line 2**: `C`

Single-letter notation is characteristic of **reflector selection**.

Thus:

`Reflector = UKW C`

- **Line 3**: `2-5-14`

This matches the numeric range used for ring settings (Ringstellung), where:

`1 = A, 2 = B, ..., 26 = Z`

So:

`2-5-14 → B E N`

- **Line 4**: `11-5-25`

Same numeric system, applied to initial rotor positions:

`11-5-25 → K E Y`

- **Line 5**: `∅`

The empty set symbol clearly indicates:

No plugboard connections

## Analysis Phase 3 — Configuration Validation

The configuration was applied using an online Enigma simulator (Cryptii)
to validate the reconstructed machine state.

The simulator output confirms the correctness of the reconstructed configuration.

<img width="1824" height="840" alt="image" src="https://github.com/user-attachments/assets/73eba7c5-8d2e-4f0a-9bb3-1cf8b81423a8" />

Got the flag!

### Final Flag

As instructed, wrap the recovered message in the flag format:

`L3m0nCTF{operatorhabitdestroyssecurity}`
