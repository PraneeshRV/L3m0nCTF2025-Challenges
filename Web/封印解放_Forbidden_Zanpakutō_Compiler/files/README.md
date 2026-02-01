# 封印解放 — Forbidden Zanpakutō Compiler

**Category:** Web | **Difficulty:** Insane | **Author:** L3m0n CTF

---

## Synopsis

After the Thousand-Year Blood War, the Kidō Corps deployed the **Reiatsu Flow Recompiler (RFR)** to restore ancient scrolls from the Hōōden sealed archives. The system adapted Urahara Kisuke's serialization concepts for spiritual data reconstruction.

During reconstruction of a forbidden manuscript, a dormant Zanpakutō spirit awakened within the compiler itself — **虚極の拘突 (Kyougoku no Kōtotsu)**.

Your mission: exploit the flawed spirit-thread protocol to manifest a phantom Zanpakutō, invoke its Bankai inside the RFR, and extract the sealed artifact.

---

## Target

```
http://<INSTANCE>:3000
```

---

## Flag Format

```
L3m0nCTF{...}
```

---

## Notes

- No authentication required
- The artifact is sealed at `/flag.txt`
- Not everything is as it appears
