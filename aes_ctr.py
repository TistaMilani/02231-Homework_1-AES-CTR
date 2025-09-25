from Crypto.Cipher import AES
import random
import os

#16bytes = 128bit
BLOCK_SIZE = 16

#generate a 16 byte key
def keygen():
    return os.urandom(16)

#given the key and the plaintext return the cyphertext encrypted (AES_ECB to encrypt a single block)
def encrypt(key, plaintext):
    
    #generate nonce
    nonce = os.urandom(BLOCK_SIZE)
    nonce_int = int.from_bytes(nonce, 'big')

    ciphertext_blocks = []
    num_blocks = (len(plaintext) + BLOCK_SIZE - 1) // BLOCK_SIZE
    
    #iterate for every block of the plaintext
    for i in range(num_blocks):
        #counter (nonce) incrementation
        counter_int = nonce_int + i
        counter_block = counter_int.to_bytes(BLOCK_SIZE, 'big')
        
        #compute F(k, r)
        Fk_i = (AES.new(key, AES.MODE_ECB)).encrypt(counter_block)
        
        #calculate actual block offsets
        start = i * BLOCK_SIZE
        end = min(start + BLOCK_SIZE, len(plaintext))
        plaintext_block = plaintext[start:end]
        
        #final XOR with for the plaintext block
        ct_block = bytes(x ^ y for x, y in zip(plaintext_block, Fk_i))
        ciphertext_blocks.append(ct_block)
        
    ct = b''.join(ciphertext_blocks)
    return nonce + ct

#given the key and the cyphertext retrieve the plaintext 
def decrypt(key, ciphertext):
    if len(ciphertext) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short: missing nonce")
    
    #separate nonce and cyphertext
    nonce = ciphertext[:BLOCK_SIZE]
    ct = ciphertext[BLOCK_SIZE:]
    
    nonce_int = int.from_bytes(nonce, 'big')
    plaintext_blocks = []
    
    num_blocks = (len(ct) + BLOCK_SIZE - 1) // BLOCK_SIZE
    
    #iterate for every block of actual cyphertext (ct)
    for i in range(num_blocks):
        
        #nonce used as the counter incremented for every block
        counter_int = nonce_int + i
        counter_block = counter_int.to_bytes(BLOCK_SIZE, 'big')
        
        #compute F(k, r)
        Fk_i = (AES.new(key, AES.MODE_ECB)).encrypt(counter_block)
        
        #calculate actual block offsets
        start = i * BLOCK_SIZE
        end = min(start + BLOCK_SIZE, len(ct))
        ct_block = ct[start:end]
        
        #final XOR with the cyphertext block
        pt_block = bytes(x ^ y for x, y in zip(ct_block, Fk_i))
        plaintext_blocks.append(pt_block)
        
    return b''.join(plaintext_blocks)

#encryption and decryption test
def enc_dec_test():
    m_rand = os.urandom(random.randint(0, 40))
    
    key = keygen()
    c = encrypt(key, m_rand)
    p = decrypt(key, c)

    print("key:         ", key.hex())
    print("random m:    ", m_rand.hex())
    print("ecrypted c:  ", c.hex())
    print("decrypted m: ", p.hex())
    print("")
    return p == m_rand


#bitflipping attack
def IND_CCA_insecurity_test(ciphertext, plaintext, payload):
    if len(ciphertext) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short: missing nonce")
    if len(payload) > len(plaintext):
        raise ValueError("Payload must be <= plaintext length")    
    
    nonce = ciphertext[:BLOCK_SIZE]
    ct = ciphertext[BLOCK_SIZE:]
    
    flip = bytes(x ^ y for x, y in zip(plaintext, payload))
    
    new_ct = bytearray(ct)
    for i in range(len(flip)):
        new_ct[i] ^= flip[i]


    return nonce + bytes(new_ct)


def main():
    print("Exercise 1.3")
    key = keygen()
    print("Random 16-byte key for this session:")
    print(key.hex(), "\n")

    while True:
        print("-------------------------MENU-------------------------")
        print("---------k=",key.hex(),"---------")
        print("1) Encrypt plaintext (utf-8 in, hex out)")
        print("2) Decrypt ciphertext (hex in, bytes out)")
        print("3) Automatic Enc-Dec test")
        print("4) Proving IND-CCA insecurity (encrypt message, flip with given payload)")
        print("5) Change key value (hex input)")
        print("0) Exit")

        choice = input("Choose an option: ").strip()
        print("")

        if choice == '1':
            plain = input("Enter plaintext to encrypt: ").encode('utf-8')
            c = encrypt(key, plain)
            print("Ciphertext in hex: ", c.hex())
            print("")
            
        elif choice == '2':
            hex_ct = input("Paste ciphertext in hex: ").strip()
            ct_bytes = bytes.fromhex(hex_ct)

            pt = decrypt(key, ct_bytes)
            print("Plaintext:", pt)
            print("")
            
        elif choice == '3':
            enc_dec_test()
            
        elif choice == '4':
            msg = input("Enter the message to encrypt: ").encode('utf-8')
            payload = input("Enter the payload to flip in (<= message length): ").encode('utf-8')

            if(len(payload) > len(msg)):
                print("Payload is longer than the message.")
                print("Aborting this test.")
                continue

            c = encrypt(key, msg)
            cm = IND_CCA_insecurity_test(c, msg, payload)

            print("")
            print("Original ciphertext in hex: ", c.hex())
            print("Modified ciphertext after bitflipping: ", cm.hex())
            print("")

            pt_orig = decrypt(key, c)
            pt_mod = decrypt(key, cm)

            print("Decrypted original plaintext: ", pt_orig)
            print("Decrypted modified plaintext: ", pt_mod)
            print("")
            
        elif choice == '5':
            hex_key = input("Paste new key in hex: ").strip()
            key = bytes.fromhex(hex_key)
            print("")
            

        elif choice == '0':
            break
        
        else:
            print("Unknown option. Please choose 0-7.\n")


if __name__ == '__main__':
    main()
