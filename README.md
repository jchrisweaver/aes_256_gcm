# aes_256_gcm
A simple python project to encrypt/decrypt files using AES 256 GCM

## Motivation

After spending WAY too much time trying to encrypt files with the standard AES encryption using OpenSSL
and other tools, I gave up and decided to just write my own.

## Usage

To encrypt a file:
    python3 encrypt_aes_256_gcm.py -in <filename> -p <password>

Encryption will produce a file named <filename>.enc.

To decrypt a file:
    python3 encrypt_aes_256_gcm.py -in <filename>.enc -p <password> -d

Decryption will produce a file named <filename>.dec.  This file should match the original file.

## Dependencies
    cryptography

