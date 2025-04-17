#!/usr/bin/env python3
"""
Enhanced Kryptos K4 Cipher Tool with Berlin Clock Options and Brute Force Capabilities
This script adds Berlin Clock-inspired base 5/12 arithmetic to the original Gromark-style cipher
with additional brute force capabilities for key expansion.
"""
import string
import itertools
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
try:
    import ipywidgets as widgets
    from IPython.display import display, HTML, clear_output
    has_ipython = True
except ImportError:
    has_ipython = False

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

def generate_key_custom_pattern(primer, length, pattern):
    """
    Generate a key sequence using a custom pattern of bases.
    
    Args:
        primer: Initial digits to seed the key generation
        length: Length of the key to generate
        pattern: List of integers representing the bases to use in sequence
    
    Returns:
        List of key digits
    """
    key_queue = [int(ch) for ch in primer if ch.isdigit()]
    if len(key_queue) < 2:
        raise ValueError("Primer must contain at least two digits.")
    
    key_stream = []
    for i in range(length):
        key_stream.append(key_queue[0])
        
        # Get the base for this position by cycling through the pattern
        base = pattern[i % len(pattern)]
        new_digit = (key_queue[0] + key_queue[1]) % base
        
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

def score_text(text, language='english'):
    """
    Score a text based on expected language characteristics.
    Higher score means more likely to be readable text.
    """
    # Simple scoring based on letter frequencies and common ngrams
    if language == 'english':
        # English letter frequencies (approximate)
        freq = {'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7, 'S': 6.3, 'H': 6.1,
                'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2,
                'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2,
                'Q': 0.1, 'Z': 0.1}
        
        # Common English bigrams
        common_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND', 
                          'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR']
        
        # Common English trigrams
        common_trigrams = ['THE', 'AND', 'THA', 'ENT', 'ING', 'ION', 'TIO', 'FOR', 'NDE', 'HAS']
        
        # Common English words
        common_words = ['THE', 'OF', 'AND', 'TO', 'IN', 'IS', 'IT', 'THAT', 'WAS', 'HE', 
                        'FOR', 'ON', 'ARE', 'AS', 'WITH', 'HIS', 'THEY', 'BE', 'AT', 'ONE']
    
    # Calculate score
    score = 0
    
    # Letter frequency score
    text_upper = text.upper()
    for char in text_upper:
        if char in freq:
            score += freq[char]
    
    # Bigram score
    for i in range(len(text) - 1):
        bigram = text_upper[i:i+2]
        if bigram in common_bigrams:
            score += 5
    
    # Trigram score
    for i in range(len(text) - 2):
        trigram = text_upper[i:i+3]
        if trigram in common_trigrams:
            score += 10
    
    # Word score
    words = text_upper.split()
    for word in words:
        if word in common_words:
            score += 20
    
    # Penalize non-alphabetic characters
    for char in text:
        if not char.isalpha() and not char.isspace():
            score -= 5
    
    # Check for repeating patterns that are unlikely in natural language
    for i in range(len(text) - 5):
        pattern = text[i:i+5]
        pattern_count = text.count(pattern)
        if pattern_count > 2:  # If the same 5-char pattern appears more than twice
            score -= pattern_count * 10
    
    return score

def process_decryption_attempt(args):
    """
    Process a single decryption attempt with given parameters.
    """
    ciphertext, primer, pattern, cipher_alphabet = args
    
    # Convert the primer to a string before passing it to generate_key_custom_pattern
    primer_str = str(primer)
    
    key_stream = generate_key_custom_pattern(primer_str, len(ciphertext), pattern)
    decryption = decrypt(ciphertext, key_stream, cipher_alphabet)
    score = score_text(decryption)
    return (score, primer, pattern, decryption)

def brute_force_decrypt(ciphertext, primer_range, keyword, base_patterns, num_results=10):
    """
    Brute force the decryption by trying different primer values and base patterns.
    """
    results = []
    cipher_alphabet = build_cipher_alphabet(keyword)
    
    # Use process pool for parallel processing
    with ProcessPoolExecutor() as executor:
        # Create a list of argument tuples for each worker task
        args_list = [(ciphertext, primer, pattern, cipher_alphabet) 
                    for primer in primer_range 
                    for pattern in base_patterns]
        
        # Submit all tasks at once
        for result in executor.map(process_decryption_attempt, args_list):
            results.append(result)
    
    # Sort by score (highest first) and return top results
    results.sort(key=lambda x: x[0], reverse=True)
    return results[:num_results]

def generate_berlin_clock_patterns(max_pattern_length=5):
    """
    Generate Berlin Clock-inspired patterns of base 5 and base 12.
    
    Args:
        max_pattern_length: Maximum length of patterns to generate
        
    Returns:
        List of base patterns
    """
    patterns = []
    
    # Add basic patterns
    patterns.append([5])                   # Pure base 5
    patterns.append([12])                  # Pure base 12
    patterns.append([5, 12])               # Alternating 5, 12
    patterns.append([5, 5, 12, 12])        # Double alternating
    
    # Add Berlin Clock-inspired patterns (4 top = base 4, 11 bottom = base 11)
    patterns.append([4, 11])
    patterns.append([4, 4, 11, 11])
    
    # Add systematic combinations
    for length in range(2, max_pattern_length + 1):
        # Generate all combinations of 5 and 12 of specified length
        for combo in itertools.product([5, 12], repeat=length):
            if list(combo) not in patterns:
                patterns.append(list(combo))
    
    return patterns

def create_colab_ui():
    """Create an interactive UI for the Kryptos cipher tool with brute force in Google Colab."""
    if not has_ipython:
        print("IPython widgets not available. Falling back to interactive mode.")
        run_interactive()
        return
    
    # Create a title
    display(HTML("<h1 style='text-align:center'>Kryptos K4 Cipher Tool with Berlin Clock Brute Force</h1>"))
    
    # Create tabs for different modes
    tab = widgets.Tab()
    tab_basic = widgets.VBox()
    tab_brute = widgets.VBox()
    
    tab.children = [tab_basic, tab_brute]
    tab.set_title(0, 'Basic Mode')
    tab.set_title(1, 'Brute Force Mode')
    
    # BASIC MODE TAB
    # --------------
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
            ('Berlin Minutes (Base 12)', 'base12'),
            ('Custom Pattern', 'custom')
        ],
        value='standard',
        description='Key Method:',
        style={'description_width': 'initial'}
    )
    
    custom_pattern_widget = widgets.Text(
        value='5,12,5,12',
        description='Custom Pattern:',
        placeholder='Comma-separated list of bases, e.g., 5,12,5,12',
        style={'description_width': 'initial'},
        layout={'width': '100%'},
        disabled=True
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
    
    # Layout the basic form
    basic_form_items = [
        widgets.HBox([widgets.VBox([mode_widget]), widgets.VBox([key_method_widget])]),
        widgets.HBox([widgets.Label('Enter text to process:')]),
        text_widget,
        widgets.HBox([widgets.VBox([primer_widget]), widgets.VBox([keyword_widget])]),
        custom_pattern_widget,
        widgets.HBox([pattern_width_widget]),
        submit_button,
        result_output
    ]
    
    tab_basic.children = basic_form_items
    
    # BRUTE FORCE TAB
    # --------------
    brute_text_widget = widgets.Textarea(
        value='OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',
        placeholder='Enter text to decrypt',
        description='Ciphertext:',
        layout={'width': '100%', 'height': '80px'}
    )
    
    brute_keyword_widget = widgets.Text(
        value='KRYPTOS',
        description='Cipher Keyword:',
        style={'description_width': 'initial'}
    )
    
    brute_primer_start_widget = widgets.Text(
        value='10000',
        description='Start Primer:',
        style={'description_width': 'initial'}
    )
    
    brute_primer_end_widget = widgets.Text(
        value='99999',
        description='End Primer:',
        style={'description_width': 'initial'}
    )
    
    brute_pattern_type_widget = widgets.Dropdown(
        options=[
            ('Berlin Clock Patterns', 'berlin'),
            ('All Base 5/12 Combinations', 'all'),
            ('Custom Pattern List', 'custom')
        ],
        value='berlin',
        description='Pattern Type:',
        style={'description_width': 'initial'}
    )
    
    brute_custom_patterns_widget = widgets.Text(
        value='5,12;12,5;5,5,12,12',
        description='Custom Patterns:',
        placeholder='Semicolon-separated list of patterns (comma-separated bases), e.g., 5,12;12,5',
        style={'description_width': 'initial'},
        layout={'width': '100%'},
        disabled=True
    )
    
    brute_num_results_widget = widgets.IntSlider(
        value=10,
        min=1,
        max=100,
        step=1,
        description='Top Results:',
        style={'description_width': 'initial'}
    )
    
    brute_submit_button = widgets.Button(
        description='Run Brute Force',
        button_style='danger',
        icon='search'
    )
    
    brute_status_widget = widgets.Label(value='')
    
    brute_result_output = widgets.Output()
    
    # Layout the brute force form
    brute_form_items = [
        widgets.HBox([widgets.Label('Enter ciphertext to decrypt:')]),
        brute_text_widget,
        widgets.HBox([widgets.VBox([brute_keyword_widget])]),
        widgets.HBox([
            widgets.VBox([brute_primer_start_widget]), 
            widgets.VBox([brute_primer_end_widget])
        ]),
        widgets.HBox([widgets.VBox([brute_pattern_type_widget])]),
        brute_custom_patterns_widget,
        widgets.HBox([brute_num_results_widget]),
        brute_submit_button,
        brute_status_widget,
        brute_result_output
    ]
    
    tab_brute.children = brute_form_items
    
    # Display the tabs
    display(tab)
    
    # Event handlers
    def on_key_method_change(change):
        if change['new'] == 'custom':
            custom_pattern_widget.disabled = False
        else:
            custom_pattern_widget.disabled = True
    
    def on_brute_pattern_type_change(change):
        if change['new'] == 'custom':
            brute_custom_patterns_widget.disabled = False
        else:
            brute_custom_patterns_widget.disabled = True
    
    key_method_widget.observe(on_key_method_change, names='value')
    brute_pattern_type_widget.observe(on_brute_pattern_type_change, names='value')
    
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
            custom_pattern = custom_pattern_widget.value
            
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
            elif key_method == 'base12':
                key_stream = generate_key_base12(primer, len(text))
                print(f"Using Berlin Clock Base 12 (minutes) key generation")
            elif key_method == 'custom':
                try:
                    pattern = [int(b) for b in custom_pattern_widget.value.split(',')]
                    if not pattern:
                        raise ValueError("Pattern cannot be empty")
                    key_stream = generate_key_custom_pattern(primer, len(text), pattern)
                    print(f"Using custom pattern: {pattern}")
                except Exception as e:
                    print(f"Error parsing custom pattern: {str(e)}")
                    return
            
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
    
    def on_brute_force_clicked(b):
        with brute_result_output:
            clear_output()
            
            # Get values from the form
            ciphertext = brute_text_widget.value
            keyword = brute_keyword_widget.value
            primer_start = brute_primer_start_widget.value
            primer_end = brute_primer_end_widget.value
            pattern_type = brute_pattern_type_widget.value
            custom_patterns = brute_custom_patterns_widget.value
            num_results = brute_num_results_widget.value
            
            # Validate input
            if not ciphertext:
                print("Error: Ciphertext is required")
                return
            
            if not primer_start.isdigit() or not primer_end.isdigit():
                print("Error: Primers must be numeric")
                return
            
            try:
                primer_range = range(int(primer_start), int(primer_end) + 1)
                # If range is too large, sample it
                if len(primer_range) > 10000:
                    print("Warning: Primer range is very large. Sampling for efficiency.")
                    primer_range = list(range(int(primer_start), int(primer_end) + 1, 
                                            max(1, (int(primer_end) - int(primer_start)) // 10000)))
            except Exception as e:
                print(f"Error with primer range: {str(e)}")
                return
            
            # Generate base patterns based on selection
            if pattern_type == 'berlin':
                base_patterns = generate_berlin_clock_patterns()
                print(f"Using {len(base_patterns)} Berlin Clock patterns")
            elif pattern_type == 'all':
                base_patterns = generate_berlin_clock_patterns(max_pattern_length=4)
                print(f"Using {len(base_patterns)} base pattern combinations")
            elif pattern_type == 'custom':
                try:
                    # Parse semicolon-separated patterns, each with comma-separated bases
                    base_patterns = []
                    pattern_strings = custom_patterns.split(';')
                    for pattern_str in pattern_strings:
                        pattern = [int(b) for b in pattern_str.split(',')]
                        if pattern:
                            base_patterns.append(pattern)
                    if not base_patterns:
                        raise ValueError("No valid patterns provided")
                    print(f"Using {len(base_patterns)} custom patterns")
                except Exception as e:
                    print(f"Error parsing custom patterns: {str(e)}")
                    return
            
            # Start time measurement
            start_time = time.time()
            brute_status_widget.value = "Brute force attack running... (This may take a while)"
            
            # Run the brute force decryption
            print(f"Starting brute force with {len(primer_range)} primers and {len(base_patterns)} patterns...")
            print(f"This will test approximately {len(primer_range) * len(base_patterns)} combinations.")
            
            # Process in smaller batches to show progress
            results = brute_force_decrypt(ciphertext, primer_range, keyword, base_patterns, num_results)
            
            # Display results
            elapsed_time = time.time() - start_time
            print(f"\nBrute force completed in {elapsed_time:.2f} seconds")
            print(f"\nTop {len(results)} results:")
            
            for i, (score, primer, pattern, decryption) in enumerate(results, 1):
                print(f"\n--- Result #{i} (Score: {score:.2f}) ---")
                print(f"Primer: {primer}")
                print(f"Pattern: {pattern}")
                print(f"Decryption: {decryption[:100]}" + ("..." if len(decryption) > 100 else ""))
                print(f"Pattern analysis (width 21):")
                patterns = analyze_text_patterns(decryption, 21)
                for line in patterns[:3]:
                    print(line)
                if len(patterns) > 3:
                    print("...")
            
            brute_status_widget.value = f"Completed in {elapsed_time:.2f} seconds"
    
    submit_button.on_click(on_submit_button_clicked)
    brute_submit_button.on_click(on_brute_force_clicked)

def run_interactive():
    """Run the interactive command-line version with brute force capabilities."""
    # The Kryptos K4 ciphertext
    ciphertext = ("OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")

    print("Kryptos K4 Cipher Tool with Berlin Clock Brute Force Options\n")
    
    # Choose between basic and brute force modes
    mode_choice = input("Select mode (1=Basic, 2=Brute Force) [1]: ").strip() or "1"
    
    if mode_choice == "2":
# BRUTE FORCE
        print("\n=== BRUTE FORCE MODE ===")
        # Get user input for brute force parameters
        keyword = input("Enter cipher keyword [KRYPTOS]: ").strip() or "KRYPTOS"
        primer_start = input("Starting primer value [10000]: ").strip() or "10000"
        primer_end = input("Ending primer value [99999]: ").strip() or "99999"
        
        # Validate primer inputs
        if not primer_start.isdigit() or not primer_end.isdigit():
            print("Error: Primers must be numeric")
            return
        
        primer_range = range(int(primer_start), int(primer_end) + 1)
        # If range is too large, sample it
        if len(primer_range) > 10000:
            print("Warning: Primer range is very large. Sampling for efficiency.")
            primer_range = list(range(int(primer_start), int(primer_end) + 1, 
                                  max(1, (int(primer_end) - int(primer_start)) // 10000)))
        
        # Select pattern type
        print("\nSelect pattern type:")
        print("1: Berlin Clock Patterns")
        print("2: All Base 5/12 Combinations")
        print("3: Custom Pattern List")
        pattern_choice = input("Selection [1]: ").strip() or "1"
        
        # Generate base patterns based on selection
        if pattern_choice == "1":
            base_patterns = generate_berlin_clock_patterns()
            print(f"Using {len(base_patterns)} Berlin Clock patterns")
        elif pattern_choice == "2":
            base_patterns = generate_berlin_clock_patterns(max_pattern_length=4)
            print(f"Using {len(base_patterns)} base pattern combinations")
        elif pattern_choice == "3":
            pattern_input = input("Enter patterns (semicolon-separated, with comma-separated bases, e.g. 5,12;12,5): ").strip()
            try:
                # Parse semicolon-separated patterns, each with comma-separated bases
                base_patterns = []
                pattern_strings = pattern_input.split(';')
                for pattern_str in pattern_strings:
                    pattern = [int(b) for b in pattern_str.split(',')]
                    if pattern:
                        base_patterns.append(pattern)
                if not base_patterns:
                    raise ValueError("No valid patterns provided")
                print(f"Using {len(base_patterns)} custom patterns")
            except Exception as e:
                print(f"Error parsing custom patterns: {str(e)}")
                return
        else:
            print("Invalid choice. Using Berlin Clock patterns.")
            base_patterns = generate_berlin_clock_patterns()
        
        num_results = int(input("Number of top results to show [10]: ").strip() or "10")
        
        print(f"\nStarting brute force with {len(primer_range)} primers and {len(base_patterns)} patterns...")
        print(f"This will test approximately {len(primer_range) * len(base_patterns)} combinations.")
        print("Running brute force attack... (This may take a while)")
        
        # Start time measurement
        start_time = time.time()
        
        # Run the brute force decryption
        results = brute_force_decrypt(ciphertext, primer_range, keyword, base_patterns, num_results)
        
        # Display results
        elapsed_time = time.time() - start_time
        print(f"\nBrute force completed in {elapsed_time:.2f} seconds")
        print(f"\nTop {len(results)} results:")
        
        for i, (score, primer, pattern, decryption) in enumerate(results, 1):
            print(f"\n--- Result #{i} (Score: {score:.2f}) ---")
            print(f"Primer: {primer}")
            print(f"Pattern: {pattern}")
            print(f"Decryption: {decryption}")
            print(f"Pattern analysis (width 21):")
            patterns = analyze_text_patterns(decryption, 21)
            for line in patterns:
                print(line)
    
    else:
        # BASIC MODE
        print("\n=== BASIC MODE ===")
        # Choose between encryption and decryption
        op_choice = input("Select operation (1=Decrypt, 2=Encrypt) [1]: ").strip() or "1"
        operation = "decrypt" if op_choice == "1" else "encrypt"
        
        # Get the text to process
        if operation == "decrypt":
            text = input(f"Enter text to decrypt [Kryptos K4]: ").strip()
            if not text:
                text = ciphertext
        else:
            text = input("Enter text to encrypt: ").strip()
        
        # Get cipher parameters
        primer = input("Enter primer (sequence of digits) [31415]: ").strip() or "31415"
        keyword = input("Enter cipher keyword [KRYPTOS]: ").strip() or "KRYPTOS"
        
        # Select key generation method
        print("\nSelect key generation method:")
        print("1: Standard (Base 10)")
        print("2: Berlin Clock (Base 5/12 alternating)")
        print("3: Berlin Hours (Base 5)")
        print("4: Berlin Minutes (Base 12)")
        print("5: Custom Pattern")
        key_method = input("Selection [1]: ").strip() or "1"
        
        # Create cipher alphabet
        cipher_alphabet = build_cipher_alphabet(keyword)
        print(f"Cipher Alphabet: {''.join(cipher_alphabet)}")
        
        # Generate the key based on selected method
        if key_method == "1":
            key_stream = generate_key_standard(primer, len(text))
            print(f"Using standard Base 10 key generation")
        elif key_method == "2":
            key_stream = generate_key_berlin(primer, len(text))
            print(f"Using Berlin Clock alternating Base 5/12 key generation")
        elif key_method == "3":
            key_stream = generate_key_base5(primer, len(text))
            print(f"Using Berlin Clock Base 5 (hours) key generation")
        elif key_method == "4":
            key_stream = generate_key_base12(primer, len(text))
            print(f"Using Berlin Clock Base 12 (minutes) key generation")
        elif key_method == "5":
            pattern_input = input("Enter custom pattern (comma-separated list of bases, e.g., 5,12,5,12): ").strip()
            try:
                pattern = [int(b) for b in pattern_input.split(',')]
                if not pattern:
                    raise ValueError("Pattern cannot be empty")
                key_stream = generate_key_custom_pattern(primer, len(text), pattern)
                print(f"Using custom pattern: {pattern}")
            except Exception as e:
                print(f"Error parsing custom pattern: {str(e)}")
                return
        else:
            print("Invalid choice. Using standard Base 10 key generation.")
            key_stream = generate_key_standard(primer, len(text))
        
        # Process the text
        if operation == "decrypt":
            result = decrypt(text, key_stream, cipher_alphabet)
            print("\nDecrypted text:")
        else:
            result = encrypt(text, key_stream, cipher_alphabet)
            print("\nEncrypted text:")
            
        print(result)
        
        # Show key stream details
        print("\nKey stream details:")
        if len(key_stream) > 30:
            display_key = key_stream[:30]
            print(f"Key (first 30 digits): {display_key}")
        else:
            print(f"Key: {key_stream}")
        
        # Get pattern width for display
        pattern_width = int(input("\nEnter width for pattern analysis [21]: ").strip() or "21")
        
        # Show the pattern analysis
        print(f"\nText displayed in width {pattern_width} format:")
        patterns = analyze_text_patterns(result, pattern_width)
        for line in patterns:
            print(line)

def main():
    """Main entry point for the script."""
    # Check if running in a notebook environment
    try:
        get_ipython
        is_notebook = True
    except NameError:
        is_notebook = False
    
    if is_notebook and has_ipython:
        # We're in a notebook environment with IPython widgets available
        create_colab_ui()
    else:
        # We're in a regular terminal
        run_interactive()

if __name__ == "__main__":
    main()
