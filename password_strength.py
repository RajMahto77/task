import getpass

def assess_password_strength(password):
    """
    Assesses the strength of a password based on the following criteria:
    - Length at least 8 characters
    - Length at least 12 characters (extra point for stronger security)
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character (non-alphanumeric)
    
    Returns the strength level ('Weak', 'Medium', 'Strong') and a list of suggestions for improvement.
    """
    criteria_met = 0
    suggestions = []

    # Check length >= 8
    if len(password) >= 8:
        criteria_met += 1
    else:
        suggestions.append("Make the password at least 8 characters long.")

    # Check length >= 12 (bonus for extra strength)
    if len(password) >= 12:
        criteria_met += 1
    else:
        suggestions.append("For better security, make the password at least 12 characters long.")

    # Check uppercase
    if any(c.isupper() for c in password):
        criteria_met += 1
    else:
        suggestions.append("Include at least one uppercase letter (A-Z).")

    # Check lowercase
    if any(c.islower() for c in password):
        criteria_met += 1
    else:
        suggestions.append("Include at least one lowercase letter (a-z).")

    # Check digit
    if any(c.isdigit() for c in password):
        criteria_met += 1
    else:
        suggestions.append("Include at least one digit (0-9).")

    # Check special character
    if any(not c.isalnum() for c in password):
        criteria_met += 1
    else:
        suggestions.append("Include at least one special character (e.g., !@#$%^&*).")

    # Determine strength level
    if criteria_met <= 2:
        strength = "Weak"
    elif criteria_met <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, suggestions

# Main script to run the tool
if __name__ == "__main__":
    print("Password Strength Assessment Tool")
    print("---------------------------------")
    password = input("Enter a password to assess: ")
    strength, suggestions = assess_password_strength(password)
    
    print(f"\nPassword Strength: {strength}")
    
    if suggestions:
        print("\nSuggestions to improve your password:")
        for suggestion in suggestions:
            print(f"- {suggestion}")
    else:
        print("\nYour password meets all criteria—great job!\n")
