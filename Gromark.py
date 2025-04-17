#!/usr/bin/env python3
"""
Enhanced Kryptos K4 Cipher Tool with Berlin Clock Options
This script adds Berlin Clock-inspired base 5/12 arithmetic to the original Gromark-style cipher.
"""
import string
import ipywidgets as widgets
from IPython.display import display, HTML, clear_output

def build_cipher_alphabet(keyword='None'):
    """
    Build a cipher alphabet.
    If a keyword is provided, letters in the keyword (in order, without repetition)
    are placed first, then the remaining letters of the alphabet in order.
    If no keyword is given, return the standard alphabet.
    """
    alphabet = string.ascii_uppercase
    if keyword and keyword.lower() != 'none':
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

def generate_key_standard(primer, length):
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

def generate_key_berlin(primer, length):
    """
    Generate a key sequence using Berlin Clock-inspired base 5 and base 12 alternation.
    
    The Berlin Clock represents hours in base 5 and minutes partly in base 12 (for 5-minute blocks).
    This function alternates between:
      - Base 5 calculations for even positions (like hours)
      - Base 12 calculations for odd positions (like minutes)
    """
    # Convert primer string digits to a list of ints
    key_queue = [int(ch) for ch in primer if ch.isdigit()]
    if len(key_queue) < 2:
        raise ValueError("Primer must contain at least two digits.")
    
    key_stream = []
    for i in range(length):
        # Add the first digit in the queue to the key stream
        key_stream.append(key_queue[0])
        
        # Determine the base for the next calculation based on position
        if i % 2 == 0:  # Even positions: use base 5 (like hours)
            new_digit = (key_queue[0] + key_queue[1]) % 5
        else:  # Odd positions: use base 12 (like minutes)
            new_digit = (key_queue[0] + key_queue[1]) % 12
        
        # Update the queue
        key_queue.pop(0)
        key_queue.append(new_digit)
    
    return key_stream

def generate_key_base5(primer, length):
    """Generate a key sequence using only base 5 arithmetic (Berlin Clock hours)."""
    key_queue = [int(ch) for ch in primer if ch.isdigit()]
    if len(key_queue) < 2:
        raise ValueError("Primer must contain at least two digits.")
    
    key_stream = []
    for _ in range(length):
        key_stream.append(key_queue[0])
        new_digit = (key_queue[0] + key_queue[1]) % 5
        key_queue.pop(0)
        key_queue.append(new_digit)
    
    return key_stream

def generate_key_base12(primer, length):
    """Generate a key sequence using only base 12 arithmetic (Berlin Clock minutes)."""
    key_queue = [int(ch) for ch in primer if ch.isdigit()]
    if len(key_queue) < 2:
        raise ValueError("Primer must contain at least two digits.")
    
    key_stream = []
    for _ in range(length):
        key_stream.append(key_queue[0])
        new_digit = (key_queue[0] + key_queue[1]) % 12
        key_queue.pop(0)
        key_queue.append(new_digit)
    
    return key_stream

def encrypt(plaintext, key_stream, cipher_alphabet):
    """
    Encrypt the plaintext using the key stream and the cipher alphabet.
    
    For each plaintext letter P at position in plain alphabet, shift right by key digit
    to find the corresponding ciphertext letter in the cipher alphabet.
    """
    plain_alphabet = list(string.ascii_uppercase)
    ciphertext = ""
    
    for ch, key_digit in zip(plaintext, key_stream):
        if ch.upper() in plain_alphabet:
            # Get the index of the plaintext letter in the standard alphabet
            i = plain_alphabet.index(ch.upper())
            # Calculate the cipher index (shifting right by key_digit, wrapping around)
            cipher_index = (i + key_digit) % 26
            # The ciphertext letter is the letter from the cipher alphabet at that index
            cipher_letter = cipher_alphabet[cipher_index]
            # Preserve case
            if ch.islower():
                cipher_letter = cipher_letter.lower()
            ciphertext += cipher_letter
        else:
            ciphertext += ch  # Non-alphabetic symbols remain unchanged
    
    return ciphertext

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

def analyze_text_patterns(text, width=21):
    """Display the text in specified width format to check for patterns."""
    pattern_display = []
    for i in range(0, len(text), width):
        pattern_display.append(text[i:i+width])
    return pattern_display

def create_colab_ui():
    """Create an interactive UI for the Kryptos cipher tool in Google Colab."""
    
    # Create a title
    display(HTML("<h1 style='text-align:center'>Kryptos K4 Cipher Tool with Berlin Clock Options</h1>"))
    
    # Create form widgets
    mode_widget = widgets.RadioButtons(
        options=['decrypt', 'encrypt'],
        value='decrypt',
        description='Mode:',
        style={'description_width': 'initial'}
    )
    
    text_widget = widgets.Textarea(
        value='OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',
        placeholder='Enter text to encrypt/decrypt',
        description='Text:',
        layout={'width': '100%', 'height': '80px'}
    )
    
    primer_widget = widgets.Text(
        value='31415',
        description='Primer:',
        style={'description_width': 'initial'}
    )
    
    key_method_widget = widgets.Dropdown(
        options=[
            ('Standard (Base 10)', 'standard'),
            ('Berlin Clock (Base 5/12 alternating)', 'berlin'),
            ('Berlin Hours (Base 5)', 'base5'),
            ('Berlin Minutes (Base 12)', 'base12')
        ],
        value='standard',
        description='Key Method:',
        style={'description_width': 'initial'}
    )
    
    keyword_widget = widgets.Text(
        value='KRYPTOS',
        description='Cipher Keyword:',
        style={'description_width': 'initial'}
    )
    
    pattern_width_widget = widgets.IntSlider(
        value=21,
        min=5,
        max=50,
        step=1,
        description='Pattern Width:',
        style={'description_width': 'initial'}
    )
    
    submit_button = widgets.Button(
        description='Run Cipher',
        button_style='primary',
        icon='check'
    )
    
    result_output = widgets.Output()
    
    # Layout the form
    form_items = [
        widgets.HBox([widgets.VBox([mode_widget]), widgets.VBox([key_method_widget])]),
        widgets.HBox([widgets.Label('Enter text to process:')]),
        text_widget,
        widgets.HBox([widgets.VBox([primer_widget]), widgets.VBox([keyword_widget])]),
        widgets.HBox([pattern_width_widget]),
        submit_button,
        result_output
    ]
    
    form = widgets.VBox(form_items)
    display(form)
    
    def on_submit_button_clicked(b):
        with result_output:
            clear_output()
            
            # Get values from the form
            mode = mode_widget.value
            text = text_widget.value
            primer = primer_widget.value
            key_method = key_method_widget.value
            keyword = keyword_widget.value
            pattern_width = pattern_width_widget.value
            
            # Validate input
            if not text:
                print("Error: Text is required")
                return
            
            if not primer or not primer.isdigit() or len(primer) < 2:
                print("Error: Primer must be at least two digits")
                return
            
            # Create cipher alphabet
            cipher_alphabet = build_cipher_alphabet(keyword)
            print(f"Cipher Alphabet: {''.join(cipher_alphabet)}")
            
            # Generate the key based on selected method
            if key_method == 'standard':
                key_stream = generate_key_standard(primer, len(text))
                print(f"Using standard Base 10 key generation")
            elif key_method == 'berlin':
                key_stream = generate_key_berlin(primer, len(text))
                print(f"Using Berlin Clock alternating Base 5/12 key generation")
            elif key_method == 'base5':
                key_stream = generate_key_base5(primer, len(text))
                print(f"Using Berlin Clock Base 5 (hours) key generation")
            else:  # base12
                key_stream = generate_key_base12(primer, len(text))
                print(f"Using Berlin Clock Base 12 (minutes) key generation")
            
            # Process the text
            if mode == 'decrypt':
                result = decrypt(text, key_stream, cipher_alphabet)
                print("\nDecrypted text:")
            else:
                result = encrypt(text, key_stream, cipher_alphabet)
                print("\nEncrypted text:")
            
            print(result)
            
            # Show key stream details
            print("\nKey stream details:")
            if len(key_stream) > 30:
                display_key = key_stream[:30] + ["..."]
            else:
                display_key = key_stream
            print(f"Key: {display_key}")
            
            # Show the pattern analysis
            print(f"\nText displayed in width {pattern_width} format:")
            patterns = analyze_text_patterns(result, pattern_width)
            for line in patterns:
                print(line)
    
    submit_button.on_click(on_submit_button_clicked)

def run():
    """Run the Colab UI version of the tool."""
    try:
        create_colab_ui()
    except Exception as e:
        print(f"Error creating UI: {str(e)}")
        print("Falling back to simple interactive mode...")
        run_interactive()

def run_interactive():
    """Run the interactive command-line version."""
    # The Kryptos K4 ciphertext
    ciphertext = ("OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")

    print("Kryptos K4 Cipher Tool with Berlin Clock Options\n")
    
    # Get the mode
    mode = input("Mode (encrypt/decrypt) [decrypt]: ").strip().lower() or "decrypt"
    
    # Get the text
    if mode == "decrypt":
        text = input(f"Enter ciphertext [Kryptos K4]: ").strip() or ciphertext
    else:
        text = input("Enter plaintext to encrypt: ").strip()
    
    # Get primer
    primer = input("Enter a primer (at least two digits) [31415]: ").strip() or "31415"
    if not primer or not primer.isdigit() or len(primer) < 2:
        print("Please enter at least two digits for the primer. Exiting.")
        return
    
    # Get key method
    print("\nSelect key generation method:")
    print("1. Standard (Base 10)")
    print("2. Berlin Clock (Base 5/12 alternating)")
    print("3. Berlin Hours (Base 5)")
    print("4. Berlin Minutes (Base 12)")
    key_method = input("Enter choice [1]: ").strip() or "1"
    
    # Get keyword
    keyword = input("\nEnter a keyword for the cipher alphabet [KRYPTOS]: ").strip() or "KRYPTOS"
    
    # Build the cipher alphabet
    cipher_alphabet = build_cipher_alphabet(keyword)
    print("\nCipher Alphabet:")
    print("".join(cipher_alphabet))
    
    # Generate the key stream based on method selected
    if key_method == "2":
        key_stream = generate_key_berlin(primer, len(text))
        print("Using Berlin Clock alternating Base 5/12")
    elif key_method == "3":
        key_stream = generate_key_base5(primer, len(text))
        print("Using Berlin Clock Base 5 (hours)")
    elif key_method == "4":
        key_stream = generate_key_base12(primer, len(text))
        print("Using Berlin Clock Base 12 (minutes)")
    else:
        key_stream = generate_key_standard(primer, len(text))
        print("Using standard Base 10")
    
    # Process the text
    if mode == "decrypt":
        result = decrypt(text, key_stream, cipher_alphabet)
        print("\nDecrypted Text:")
    else:
        result = encrypt(text, key_stream, cipher_alphabet)
        print("\nEncrypted Text:")
    
    print(result)
    
    # Show pattern analysis
    width = int(input("\nEnter width for pattern analysis [21]: ").strip() or "21")
    print(f"\nText in width {width} format:")
    patterns = analyze_text_patterns(result, width)
    for line in patterns:
        print(line)

# Main execution
if __name__ == "__main__":
    try:
        # Check if running in Google Colab
        import google.colab
        is_colab = True
    except ImportError:
        is_colab = False
    
    if is_colab:
        run()
    else:
        run_interactive()
else:
    # If imported as a module in a notebook, prepare to run
    print("Berlin Clock Kryptos Cipher module imported. Run the 'run()' function to start.")
