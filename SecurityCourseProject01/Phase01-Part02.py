import itertools
import string
import time

attemps = 0


def bruteforce_cracker(password, mode, character_set, k):
    global attemps
    digits = '0123456789'
    digits_and_lower = '0123456789abcdefghijklmnopqrstuvwxyz'
    lower = 'abcdefghijklmnopqrstuvwxyz'
    all = string.printable

    if int(character_set) == 1:
        chars = digits
    elif int(character_set) == 2:
        chars = digits_and_lower
    elif int(character_set) == 3:
        chars = lower
    else:
        chars = all

    if int(mode) == 1:
        for combination in itertools.product(chars, repeat=len(password)):
            # Join the characters in the combination to form a password candidate
            candidate = "".join(combination)
            attemps += 1
            # Check if the candidate matches the password
            if candidate == password:
                return candidate
    else:
        for length in range(1, len(password) + 1 - int(k)):
            for combination in itertools.product(chars, repeat=length):
                # Join the characters in the combination to form a password candidate
                candidate = "".join(combination)
                attemps += 1
                # Check if the candidate matches the password
                if candidate == password[-(len(password) - int(k)):]:
                    return password[:int(k)] + candidate


print("Working modes: ")
print("1: Standard mode providing only length of passwprd ")
print("2: Search mode providing only first character of password  ")
print("3: Search mode providing only k character of password  ")
mode = input("Insert your mode:  ")

print()

print("Choose k: 0 for mode 1, 1 for mode 2, and k for mode 3")
k = input("Insert k:   ")

print()

print("Chatcter sets:   ")
print("1: only digit")
print("2: only digit and lowercase alphabet")
print("3: only lowercase alphabet")
print("4: any type of character")
character_set = input("Insert your character set:   ")

print()

password = input("Insert your password:  ")

print()

start = time.time()
cracked_password = bruteforce_cracker(password, mode, character_set, k)
end = time.time()

print("Cracked password is:  ", cracked_password)
print("Number of attemps:  ", attemps)
print("Time taken:  ", end - start)
