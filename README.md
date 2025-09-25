# AES CTR for exercise 1.3
This code implement a AES_CTR by using AES-ECB to encrypt counter blocks

## Compilation and Installation
This script uses `python3` and `pycryptodome` library.

Tested on `Ubuntu 24.04 LTS`, `python-3.12` and `pycryptodome-3.23`.
Install with:
```bash
pip install pycryptodome
```

Run the script and follow the on-screen menu:
```bash
python3 aes_ctr.py
```

## Running the Tests

When you start the program, the key is generated for the session. You’ll then see the following menu:

```
-------------------------MENU-------------------------
---------k= <hex-key> ---------
1) Encrypt plaintext (utf-8 in, hex out)
2) Decrypt ciphertext (hex in, bytes out)
3) Automatic Enc-Dec test
4) Proving IND-CCA insecurity (encrypt message, flip with given payload)
5) Change key value (hex input)
0) Exit
Choose an option: 
```

Here’s what each option does:

### 1) Encrypt plaintext (utf-8 in → hex out)
- **Input**: a UTF-8 string.
- **Action**: encrypts it with the session key.
- **Output**: ciphertext in hexadecimal form.

### 2) Decrypt ciphertext (hex in → bytes out)
- **Input**: ciphertext as hex string.
- **Action**: decrypts with the session key.
- **Output**: plaintext as raw bytes (may not always print nicely if non-UTF8).

### 3) Automatic Enc-Dec Test
- Runs an automatic test: encrypts a random message, then decrypts it, and shows that the decrypted result matches the original.

### 4) Proving **IND-CCA Insecurity**
- **Input**: a message and a payload (must be shorter or equal to message length).
- **Action**: 
  - Encrypts the message.
  - Modifies ciphertext by flipping bits using the payload.
  - Decrypts both original and modified ciphertexts.
- **Output**: shows how flipping bits in ciphertext modifies the decrypted message (demonstrating malleability).

### 5) Change Key Value (hex input)
- **Input**: a new 16-byte key in hex form.
- **Action**: replaces the current key with the new one.

### 0) Exit
- Exits the program.
