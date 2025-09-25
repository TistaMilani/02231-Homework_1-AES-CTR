# AES CTR for exercise 1.3
This code implement a AES_CTR by using AES-ECB to encrypt counter blocks

## Requirements
This script uses the `pycryptodome` library. Install with:
```bash
pip install pycryptodome
```

## Usage
Run the script and follow the on-screen menu:
```bash
python3 aes_ctr.py
```

## ENC-DEC explanation (CTR mode)
Encryption of a single block (index `i`):

```
counter = nonce + i
Fk_i = AES_ECB(key, counter)
c_i = p_i ⊕ Fk_i
```

Decryption simply XORs the same `Fk_i` with `c_i` to recover `p_i`:

```
p_i = c_i ⊕ Fk_i
```

### Bitflipping explanation
CTR mode is malleable: flipping bits in the ciphertext flips the corresponding bits in the plaintext after decryption.
Consider a ciphertext block `c_i` corresponding to plaintext block `p_i`:

```
c_i = p_i ⊕ Fk_i
```

During decryption:

```
c_i ⊕ Fk_i
(p_i ⊕ Fk_i) ⊕ Fk_i
p_i
```


If an attacker modifies the ciphertext block to `c_i' = c_i ⊕ flip`, the decrypted block becomes:
```
c_i' ⊕ Fk_i
(p_i ⊕ Fk_i ⊕ flip) ⊕ Fk_i
p_i ⊕ flip
```


So the attacker can change the plaintext in a controlled way by XORing a `flip` mask into the ciphertext. In the provided script the is constructed `flip = plaintext_prefix ⊕ payload` and XOR it to the ciphertext's corresponding bytes so the decrypted plaintext prefix becomes `payload`.

