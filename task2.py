import numpy as np
import matplotlib.image as mpimg

def xor_pixels(image_path, output_path, key):
    """
    Performs XOR operation on each pixel of the image with the given key.
    This function handles both encryption and decryption since XOR is involutory.
    """
    # Load the image
    img = mpimg.imread(image_path)
    
    # Convert to uint8 if necessary (matplotlib may load as float32)
    if img.dtype != np.uint8:
        img = (img * 255).astype(np.uint8)
    
    # Perform XOR on each pixel
    processed_img = np.bitwise_xor(img, key)
    
    # Save the processed image
    mpimg.imsave(output_path, processed_img)

def main():
    print("Simple Image Encryption/Decryption Tool using Pixel XOR")
    print("Note: Encryption and decryption use the same operation.")
    
    while True:
        print("\nOptions:")
        print("1. Encrypt an image")
        print("2. Decrypt an image")
        print("3. Exit")
        
        choice = input("Choose an option (1-3): ")
        
        if choice == '3':
            print("Goodbye!")
            break
        
        if choice not in ['1', '2']:
            print("Invalid choice! Please select 1, 2, or 3.")
            continue
        
        input_path = input("Enter the input image path (e.g., input.png): ").strip('"')
        output_path = input("Enter the output image path (e.g., output.png): ").strip('"')
        
        try:
            key = int(input("Enter the key (0-255): "))
            if not 0 <= key <= 255:
                print("Key must be between 0 and 255.")
                continue
        except ValueError:
            print("Invalid key! Please enter an integer.")
            continue
        
        xor_pixels(input_path, output_path, key)
        
        action = "Encrypted" if choice == '1' else "Decrypted"
        print(f"{action} image saved to {output_path}")

if __name__ == "__main__":
    main()