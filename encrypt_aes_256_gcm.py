import argparse
import base64
import secrets
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_SIZE = 32  # 256 bits
ITERATION_COUNT = 100000

VERSION = 1 # version of this script

class InvalidPassword(Exception):
    pass

def encrypt(data_input: bytes | str, password: str) -> str:
    """Decrypts a ciphertext using a password.

    Args:
        data_input: The data to encrypt. Can be either bytes or str.
        password: The password to use for encryption.

    Returns:
        The encrypted data as bytes.
    """
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)

    data_input_bytes = data_input.encode() if isinstance(data_input, str) else data_input

    aesgcm = AESGCM(key)

    # NIST recommends a 96-bit IV length for best performance
    # https://csrc.nist.gov/pubs/sp/800/38/d/final
    # Can be up to 264 - 1 bits. NEVER REUSE A NONCE with a key.
    nonce = secrets.token_bytes(12) # 96 bits

    # use the salt as the additional authenticated data
    ciphertext = aesgcm.encrypt(nonce, data_input_bytes, salt)

    return (
        f"{base64.b64encode(ciphertext).decode('utf-8')}:"
        f"{base64.b64encode(nonce).decode('utf-8')}:"
        f"{base64.b64encode(salt).decode('utf-8')}"
    )


def decrypt(ciphertext: str, password: str) -> bytes:
    """Decrypts a ciphertext using a password.

    Args:
        ciphertext: The ciphertext to decrypt.
        password: The password to use for decryption.

    Returns:
        The decrypted plaintext as bytes. If the decrypted plaintext is not
        valid UTF-8, it is returned as bytes.

    Raises:
        InvalidPassword: If the password is invalid.
    """
    ciphertext, nonce, salt = [base64.b64decode(x) for x in ciphertext.split(':')]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        data_out = aesgcm.decrypt(nonce, ciphertext, salt)
    except InvalidTag as e:
        raise InvalidPassword("Invalid password")

    try:
        return data_out.decode('utf-8')
    except UnicodeDecodeError:
        return data_out

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key from a password and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: The password to derive the key from.
        salt: The salt to use for the derivation.

    Returns:
        The derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATION_COUNT,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def change_file_extension(file_name: str, new_extension: str, old_extension: str | None = None) -> str:
    """Changes the file extension of a file name.

    Args:
        file_name: The file name to modify.
        old_extension: The old extension (without the dot).
        new_extension: The new extension (without the dot).

    Returns:
        The modified file name with the new extension.
    """
    if old_extension and file_name.endswith(f".{old_extension}"):
        return file_name.removesuffix(f".{old_extension}") + "." + new_extension
    return f"{file_name}.{new_extension}"

def main():

    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file')

    # Version argument as an optional flag
    parser.add_argument('-v', '--version', action='store_true', help='Display the version of the program')

    # File operation arguments
    parser.add_argument('-in', '--input_file', help='Input filename to encrypt/decrypt')
    parser.add_argument('-d', '--decrypt', action='store_true', default=False, help='Flag to decrypt the file instead of encrypting it')
    parser.add_argument('-p', '--password', help='Password used for encryption and decryption')

    args = parser.parse_args()

    # Check for version request
    if args.version:
        print( f"Version { VERSION }")
        sys.exit()

    # Since version wasn't specified, input_file and password must be provided
    if not args.input_file or not args.password:
        parser.error("the following arguments are required: -in/--input_file, -p/--password")

    try:
        with open(args.input_file, 'rb') as input_file:
            input_data = input_file.read()
    except FileNotFoundError:
        print(f'File {args.input_file} not found')
        return

    if args.decrypt:
        try:
            input_data = input_data.decode('utf-8')
        except UnicodeDecodeError:
            print(f'File {args.input_file} does not appear to be encrypted')
            return

        output_filename = change_file_extension(args.input_file, 'dec', 'enc')
        try:
            output_data = decrypt(input_data, args.password)
        except ValueError:
            print(f'File {args.input_file} does not appear to be encrypted')
            return
        except InvalidPassword:
            print(f'Invalid password')
            return
    else:
        output_filename = change_file_extension(args.input_file, 'enc' )
        output_data = encrypt(input_data, args.password)

    if isinstance(output_data, str):
        file_type = 'wt'
    else:
        file_type = 'wb'
    try:
        with open(output_filename, file_type) as output_file:
            output_file.write(output_data)
    except NameError:  # If the file is not encrypted
        print(f'File {args.input_file} does not appear to be encrypted')
        return

if __name__ == "__main__":
    main()
