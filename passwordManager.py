from getpass import getpass
from argon2 import PasswordHasher, exceptions

def main():
    startup()
    username = inputUsername()
    password = inputPassword()

def inputUsername():
    usernameInput = input("Enter your username: ")
    while len(usernameInput) == 0:
        print("Username must not be empty. Please enter your username: ")
        usernameInput = input("Enter your username:")
    return usernameInput

def inputPassword():
    passwordInput = getpass("Enter your password: ")
    while len(passwordInput) == 0:
        print("Password must not be empty. Please enter your password: ")
        passwordInput = getpass("Enter your password:")
    return passwordInput

def inputMasterPassword():
    masterPassword = getpass("Welcome. Create your master password: ")
    while not checkPasswordStrength(masterPassword):
        masterPassword = getpass("Master password must be at least 8 characters long and include at least one uppercase character, at least one digit and at least one uppercase character.\nPlease create your master password: ")
    return masterPassword

def startup():
    ph = PasswordHasher()
    with open("masterPassword.vault_auth","r") as file:
        masterPasswordHashed = file.readline().strip()
    if len(masterPasswordHashed) == 0:
        masterPassword = inputMasterPassword()
        masterPasswordHashed = ph.hash(masterPassword)
        with open("masterPassword.vault_auth", "w") as file:
            file.write(masterPasswordHashed)
    else:
        login()

def checkPasswordStrength(password):
    specialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
    if len(password) < 8:
        return False
    hasDigit = False
    for i in password:
        if i.isdigit():
            hasDigit = True
    if not hasDigit:
        return False
    hasSpecialChars = False
    for i in password:
        if i in specialChars:
            hasSpecialChars = True
    if not hasSpecialChars:
        return False
    hasUpperCase = False
    for i in password:
        if i.isupper():
            hasUpperCase = True
    if not hasUpperCase:
        return False
    return True

def login():
    passwordHasher = PasswordHasher()
    with open("masterPassword.vault_auth", "r") as f:
        hash = f.read()
    input = ""
    isCorrect = False
    while isCorrect == False:
        try:
            input = getpass("Enter your master password: ")
            passwordHasher.verify(hash, input)
            print("Password is correct")
            isCorrect = True
        except exceptions.VerifyMismatchError:
            print("incorrect password, please try again")
            


if __name__ == "__main__":
    main()