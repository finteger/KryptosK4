#!/usr/bin/env python3
import string

def build_cipher_alphabet(keyword='None'):
    """
    Build a cipher alphabet.
    If a keyword is provided, letters in the keyword (in order, without repetition)
    are placed first, then the remaining letters of the alphabet in order.
    If no keyword is given, return the standard alphabet.
    """
    alphabet = string.ascii_uppercase
    if keyword:
        keyword = "".join([ch for ch in keyword.upper() if ch in alphabet])
        seen = set()
        cipher = []
        for ch in keyword:
            if ch not in seen:
                cipher.append(ch)
                seen.add(ch)
        for ch in alphabet:
            if ch not in seen:
                cipher.append(ch)
        return cipher
    else:
        return list(alphabet)

def generate_key(primer, length):
    """
    Generate a key sequence (list of integers) for the given length using a lagged Fibonacci generator.

    The algorithm works by:
      - Starting with the digits of the primer (as integers).
      - Then repeatedly:
          * Take the sum modulo 10 of the first two digits in the current queue.
          * Append the new digit.
          * Remove the first digit (simulate a shifting window).

    This yields a keystream of digits as long as needed.
    """
    # Convert primer string digits to a list of ints.
    key_queue = [int(ch) for ch in primer if ch.isdigit()]
    if len(key_queue) < 2:
        raise ValueError("Primer must contain at least two digits.")

    key_stream = []
    # Generate key_stream by running the generator until reaching desired length.
    # For the purpose of this decryption, we want one key digit for each ciphertext character.
    for _ in range(length):
        # The first digit in the current queue is part of the key.
        key_stream.append(key_queue[0])
        # Compute next digit: sum of the first two digits mod 10.
        new_digit = (key_queue[0] + key_queue[1]) % 10
        # Remove the first digit and append the new digit.
        key_queue.pop(0)
        key_queue.append(new_digit)
    return key_stream

def decrypt(ciphertext, key_stream, cipher_alphabet):
    """
    Decrypt the ciphertext using the key stream and the cipher alphabet.

    Encryption (hypothetical):
      For each plaintext letter P, the letter in the plain alphabet (A-Z) is at column i.
      The corresponding 'base' letter from the cipher alphabet at column i is shifted right by key digit n
      (cyclically) to yield the ciphertext letter.

    Therefore, decryption works by:
      - Finding the position j of the ciphertext letter in the cipher alphabet.
      - Shifting left by the corresponding key digit (i.e. subtracting the key digit modulo 26).
      - That position in the cipher alphabet corresponds to column i,
        so the plaintext letter is simply the letter from the standard alphabet at that index.

    Non-alphabet characters are left unchanged.
    """
    plain_alphabet = list(string.ascii_uppercase)
    plaintext = ""

    for ch, key_digit in zip(ciphertext, key_stream):
        if ch.upper() in cipher_alphabet:
            # Get the index of the ciphertext letter in the cipher alphabet.
            j = cipher_alphabet.index(ch.upper())
            # Calculate the base index (shifting left by key_digit, wrapping around)
            base_index = (j - key_digit) % 26
            # The plaintext letter is the letter from the plain alphabet at the base index.
            # Preserve case: if the ciphertext was lowercase, convert result to lowercase.
            plain_letter = plain_alphabet[base_index]
            if ch.islower():
                plain_letter = plain_letter.lower()
            plaintext += plain_letter
        else:
            plaintext += ch  # Non-alphabetic symbols remain unchanged.
    return plaintext

def main():
    # The Kryptos K4 ciphertext
    ciphertext = ("OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")

    print("Hypothetical Kryptos K4 Decryption Using a Gromark‐Style Algorithm\n")
    print("Enter a five-digit primer (e.g., 31415).")
    primer = input("Primer: ").strip()
    if not primer or not primer.isdigit() or len(primer) < 2:
        print("Please enter at least two digits for the primer. Exiting.")
        return

    # Optionally allow a keyword to modify the cipher alphabet.
    print("\n(Optional) Enter a keyword for creating a custom cipher alphabet. (Press Enter to use the standard alphabet A-Z)")
    keyword = input("Keyword: ").strip()

    # Build the cipher alphabet.
    cipher_alphabet = build_cipher_alphabet(keyword)
    print("\nCipher Alphabet:")
    print(" ".join(cipher_alphabet))

    # Generate the key stream of the same length as the ciphertext.
    key_stream = generate_key(primer, len(ciphertext))

    # Decrypt the ciphertext.
    plaintext = decrypt(ciphertext, key_stream, cipher_alphabet)

    print("\nDecrypted Plaintext (hypothetical):")
    print(plaintext)

if __name__ == '__main__':
    main()
