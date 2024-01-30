"""
A script that performs a dictionary attack on an example CSV containing usernames and hashed passwords. 
"""

import hashlib
import csv
from urllib.request import urlopen

def read_wordlist(url):
    """ Takes a URL and returns the file content """
    try:
        wordlist_file = urlopen(url).read()
    except Exception as e:
        print("There was an error while reading the wordlist, error:", e)
        exit()
    return wordlist_file

def hash_password(password):
    """ 
    Takes the password and returns the SHA256 hash of the password as a double-
    length string, containing only hexadecimal digits.
    """
    result = hashlib.sha256(password.encode())
    return result.hexdigest()

# Passing the Rockyou-75 password wordlist url. Contains 59,184 passwords.
url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou-75.txt'

# Reading hashed passwords and usernames from CSV
CSV_FILE_PATH = 'hashed_passwords.csv'

# Dictionary to store username-password pairs
user_password_dict = {}

with open(CSV_FILE_PATH, mode='r') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        username = row['username']
        hashed_password = row['hashed_password']
        user_password_dict[hashed_password] = username

# Reading wordlist from rockyou-75.txt and converting to SHA256
wordlist = read_wordlist(url).decode('UTF-8')
#
rockyou_passwords = [password.strip() for password in wordlist.split('\n')]
#
rockyou_hashes = [hash_password(password) for password in rockyou_passwords]

# Running the dictionary attack
matches = set(user_password_dict.keys()) & set(rockyou_hashes)

# Displaying results
if matches:
    print("Password matches found...")
    for match in matches:
        print("Username:", user_password_dict[match], "   \tPassword:     ", rockyou_passwords[rockyou_hashes.index(match)])
else:
    print("No password matches found.")
