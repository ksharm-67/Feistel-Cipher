import argparse
import hashlib

parser = argparse.ArgumentParser(description="Feistel Cipher")                          #parse the given arguments
parser.add_argument("--plaintext")
parser.add_argument("--key")
parser.add_argument("--rounds", type=int)
    
args = parser.parse_args()

def feistel_round(half: str, round_key: str) -> str:                                    #implement the feistel round function
    
    result = int(half, 2) ^ int(round_key, 2)                                           #xor the half with the round key after conversion to binary
    
    return format(result, '032b')             
     
def generate_round_key(key: str, round_number: int) -> str:                             #function to generate the key for each round
    
    round_input = key + str(round_number)                                               #concatenate the key with round number
    hash_value = hashlib.sha256(round_input.encode()).hexdigest()[:8]                   #encrypt using sha-256 and get the first 8 bits only
    
    return format(int(hash_value, 16), '032b')

def encrypt(plaintext: str, key: str, num_rounds: int) -> str:
    
    hex_text = ''.join(format(ord(c), '02x') for c in plaintext)                        #convert to hex from plaintext
    
    if len(hex_text) % 16 != 0:                                                         #ensure that we have only 8 bytes per block
        hex_text = hex_text.ljust((len(hex_text)//16 + 1)*16, '0')

    ciphertext = ''
    
    for i in range(0, len(hex_text), 16):
        block = hex_text[i:i+16]                                                        #process our hex input block by block
        binary = format(int(block, 16), '064b')

        left = binary[:len(binary)//2]                                                  #separate into halves
        right = binary[len(binary)//2:]

        for j in range(num_rounds):
            round_key = generate_round_key(key, j)                                      
            new_right = feistel_round(right, round_key)                                 #perform the feistel function on the right half
            new_left = format(int(left, 2) ^ int(new_right, 2), f'0{len(binary)//2}b')  #calculate the new left
            left, right = right, new_left                                               #swap the left and right
        
        finalb = left + right                                                           #concatenate the blocks
        ciphertext += format(int(finalb, 2), '016x')                                    #convert back to hex

    return ciphertext


def decrypt(ciphertext: str, key: str, num_rounds: int) -> str:
    
    plaintext = ''

    for i in range(0, len(ciphertext), 16):                                             #process our hex input block by block
        block = ciphertext[i:i+16]
        binary = format(int(block, 16), '064b')

        left = binary[:len(binary)//2]                                                  #separate into halves
        right = binary[len(binary)//2:]

        for j in range(num_rounds - 1, -1, -1):                                         #do the same thing we did before, but in reverse
            round_key = generate_round_key(key, j)
            new_left = feistel_round(left, round_key)
            new_right = format(int(right, 2) ^ int(new_left, 2), f'0{len(binary)//2}b')
            left, right = new_right, left

        finalb = left + right
        decrypted_bytes = bytes(int(finalb[i:i+8], 2) for i in range(0, len(finalb), 8))

        plaintext += decrypted_bytes.decode('utf-8')                                    #convert to utf-8 as ascii might give errors

    return plaintext.rstrip('\x00')                                                     #remove extra zeroes

hex_text = ''.join(format(ord(c), '02x') for c in args.plaintext)[:16].ljust(16, '0')   
                                                                                        #print our results
result = encrypt(args.plaintext, args.key, args.rounds)
decrypted = decrypt(result, args.key, args.rounds)

print(f"Original text: {args.plaintext}")
print(f"Encrypted: {result}")
print(f"Decrypted: {decrypted}")