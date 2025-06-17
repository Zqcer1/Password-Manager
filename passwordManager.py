from getpass import getpass
from argon2 import PasswordHasher, exceptions
from cryptography.fernet import Fernet
import json

def main():
    passwordManager = PasswordManager()


class PasswordManager():

    __masterPassword: str = ""
    __userPasswordCombo = {}
    __userPasswordComboEncrypted = {}

    def __init__(self):
        self.__masterPassword = self.startup()
        self.__userPasswordComboEncrypted,self.__userPasswordCombo = self.loadUserPasswordCombo()
        return

    def loadUserPasswordCombo(self):
        with open("vault.json",'r') as file:
            userPasswordComboEncrypted = json.load(file)
        userPasswordComboDecrypted = []
        for i in userPasswordComboEncrypted:
            salt = i["salt"].encode("utf-8")
            token = i["password"].encode("utf-8")
            password = self.decrypt(token, self.deriveKey(self.getMasterPassword,salt))
            userPasswordComboEncrypted.append({
                "website":i["website"],
                "salt":i["salt"],
                "username":i["username"],
                "password":password
            })
        return (userPasswordComboDecrypted,userPasswordComboEncrypted)

    def getMasterPassword(self):
        return self.__masterPassword
    
    def getUserPasswordComboEncrypted(self):
        return self.__userPasswordComboEncrypted
    
    def getUserPasswordCombo(self):
        return self.__userPasswordCombo
    
    def deriveKey(self,plaintext: str, salt: bytes):
        passwordHasher = PasswordHasher()
        return passwordHasher.hash(bytes(plaintext) + salt) 
    
    def encrypt(plaintext: str, key: bytes) -> bytes:
        return Fernet.encrypt(plaintext,key)
    
    def decrypt(token: bytes, key: bytes) -> str:
        return Fernet.decrypt(token,key)

    def inputUsername(self):
        usernameInput = input("Enter your username: ")
        while len(usernameInput) == 0:
            print("Username must not be empty. Please enter your username: ")
            usernameInput = input("Enter your username:")
        return usernameInput

    def inputPassword(self):
        passwordInput = getpass("Enter your password: ")
        while len(passwordInput) == 0:
            print("Password must not be empty. Please enter your password: ")
            passwordInput = getpass("Enter your password:")
        return passwordInput

    def checkPasswordStrength(self,password):
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
    
    def inputMasterPassword(self):
        masterPassword = getpass("Welcome. Create your master password: ")
        while not self.checkPasswordStrength(masterPassword):
            masterPassword = getpass("Master password must be at least 8 characters long and include at least one uppercase character, at least one digit and at least one uppercase character.\nPlease create your master password: ")
        return masterPassword
    
    def login(self):
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
        return input

    def startup(self):
        ph = PasswordHasher()
        with open("masterPassword.vault_auth","r") as file:
            masterPasswordHashed = file.readline().strip()
        if len(masterPasswordHashed) == 0:
            masterPassword = self.inputMasterPassword()
            masterPasswordHashed = ph.hash(masterPassword)
            with open("masterPassword.vault_auth", "w") as file:
                file.write(masterPasswordHashed)
                return masterPassword
        else:
            return self.login()





if __name__ == "__main__":
    main()