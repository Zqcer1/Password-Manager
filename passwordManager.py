def main():
    print("Welcome to PasswordManager")
    username = inputUsername()
    password = inputPassword()
    

def inputUsername():
    usernameInput = input("Enter your username: ")
    while len(usernameInput) == 0:
        print("Username must not be empty. Please enter your username: ")
        usernameInput = input("Enter your username:")
    return usernameInput

def inputPassword():
    passwordInput = input("Enter your password: ")
    while len(passwordInput) == 0:
        print("Password must not be empty. Please enter your password: ")
        passwordInput = input("Enter your password:")
    return passwordInput

if __name__ == "__main__":
    main()