# Feistel-Cipher

This project encrypts a given 16-bit plaintext by applying Fiestel rounds on it. You need to have python3 to run it. You can install python from https://www.python.org/downloads/ and add it to PATH.

You provide the arguments in the following way:

python3 FiestelCipher.py --plaintext "<Enter your 16-bit plaintext here"> --key <"Enter the initial key here"> --rounds <Enter number of rounds here>

The program will take the plaintext, apply the feistel rounds to it, i.e. it will tak your key, generate a new one according to the round number and hashing it with SHA-256, then it will xor the key with the right half of the (binary) plaintext, xor the left with the new right half, then swap the halves. 

It will then display the encrypted text. 

After that, it will apply the former functions in reverse, and display the decrypted plaintext (which will be the same as the initial input).

By Kavish Sharma
