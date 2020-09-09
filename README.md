# tawny-cipher
Tawny Cipher (or TC256) is a custom symmetric encryption algorithm I created. It is used to make plaintext unreadable by encrypting it with a key. This is a 256 bit encryption so the key and IV must be 256 bits/32 bytes.

OpenSSL Library required for example compilation.

____________________________________________

# Compilation
    $ cd examples/
    $ gcc -o encrypt encrypt.c -I ../ -lcrypto
    $ gcc -o decrypt decrypt.c -I ../ -lcrypto
    
# Usage
`examples/encrypt.c` and `examples/decrypt.c` are example on how to encrypt and decrypt data using this cipher.
The encrypt example reads a plaintext file (as the first argument) with an unencrypted message and encrypts it using a file with a 256 bit key (as the second argument).

I have included two example files in the `examples/files` folder:

- `examples/files/plaintext.txt` is an example plaintext message which can be read. Put anything you like in there!
- `examples/files/key.bin` is an example key file, containing random hex characters which have been randomly generated. You can generate your own key file too.

To encrypt your file, use `./encrypt [PLAINTEXT FILE] [KEY FILE] [OUT FILE]`. Here's an example:

    $ ./encrypt  files/plaintext.txt  files/key.bin  encrypted.bin

The program then reads the plaintext and encrypts it using the key. This program generates a random initialization vector which you need to keep hold of if you're manually using the `tawny.h` header file. This example program does it automatically.
It then saves the encrypted text (ciphertext) to your specified output filename (third argument) and puts the initialization vector as the last 32 bytes of the ciphertext for the decryption program to use. It is important to keep the key and initialization vector when encrypting. If you are using the example programs, do not edit the generated ciphertext file after encryption, or you will not be able to decrypt it.

To decrypt the ciphertext file, use `./decrypt [CIPHERTEXT FILE] [KEY FILE] [OUT FILE]`. Here's an example:

    $ ./decrypt  encrypted.bin  files/key.bin  decrypted.txt
    
The program then reads the ciphertext file and decrypts it using the key.
It then saves the decrypted text to `decrypted.txt` and is readable again.

# This is a test version #

TODO: Remove example functions?

TODO: Add options for base64 encoding

TODO: Provide alternative for manual pkcs#7 padding (pkcs7pad())

