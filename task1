def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            # Determine the case and base ASCII value
            ascii_base = ord('A') if char.isupper() else ord('a')
            # Shift the character and wrap around the alphabet
            encrypted_char = chr((ord(char) - ascii_base + shift) % 26 + ascii_base)
            encrypted_text += encrypted_char
        else:
            # Keep non-alphabetic characters unchanged
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(text, shift):
    # Decryption is encryption with negative shift
    return caesar_encrypt(text, -shift)

def main():
    while True:
        print("\nCaesar Cipher Program")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        
        choice = input("Choose an option (1-3): ")
        
        if choice == '3':
            print("End the Program!")
            break
            
        if choice not in ['1', '2']:
            print("Invalid choice! Please select 1, 2, or 3.")
            continue
            
        message = input("Enter the message: ")
        try:
            shift = int(input("Enter the shift value (1-25): "))
            if not 1 <= shift <= 25:
                print("Shift value must be between 1 and 25.")
                continue
        except ValueError:
            print("Invalid shift value! Please enter a number.")
            continue
            
        if choice == '1':
            result = caesar_encrypt(message, shift)
            print(f"Encrypted message: {result}")
        else:
            result = caesar_decrypt(message, shift)
            print(f"Decrypted message: {result}")

if __name__ == "__main__":
    main()
