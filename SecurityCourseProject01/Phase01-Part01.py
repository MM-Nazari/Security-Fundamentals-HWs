import re

is_short = False
is_long = False
has_properly_length = False
has_lower = False
has_upper = False
has_digit = False
has_special_character = False
is_in_blacklist = False

blaclist = {
    1: "123456",
    2: "123456789",
    3: "12345",
    4: "111111",
    5: "1234567890",
    6: "qwerty",
    7: "password",
    8: "ramz",
    9: "admin",
    10: "user",
    11: "letmein",
    12: "abc",
    13: "1q2w3e",
    14: "ali",
    15: "mohammad",
    16: "hasan",
    17: "hossein",
    18: "reza",
    19: "amir",
    20: "fateme",
    21: "zahra",
    22: "esteghlal",
    23: "perspolis",
    24: "real",
    25: "barcelona",
    26: "liverpool",
    27: "manchester",
    28: "123",
    29: "1234",
    30: "nazari"
}


def password_strength_checker(password, blaclist):
    global is_short
    global is_long
    global is_in_blacklist
    global has_digit
    global has_upper
    global has_lower
    global has_special_character
    global has_properly_length
    counter = 0

    # Check length
    if len(password) < 8:
        is_short = True
    elif len(password) > 20:
        is_long = True
    else:
        has_properly_length = True
        counter += 1

    # Check uppercase
    if re.search(r'[A-Z]', password):
        has_upper = True
        counter += 1

    # Check lowercase
    if re.search(r'[a-z]', password):
        has_lower = True
        counter += 1

    # Check digit
    if re.search(r'[0-9]', password):
        has_digit = True
        counter += 1

    # Check if the password contains at least one special character
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        has_special_character = True
        counter += 1

    # Check blacklist
    for key in blaclist:
        if re.search(blaclist[key], password):
            is_in_blacklist = True
            break

    if not is_in_blacklist:
        counter += 1

    return counter


password = input("Input your password: ")
score = password_strength_checker(password, blaclist)

print()

# check score
if score == 0 or score == 1 or score == 2:
    print("Password is Weak")
if score == 3 or score == 4:
    print("Password is Medium")
if score == 5 or score == 6:
    print("Password is Strong")

print()

# Strength of password
print("Strength of your password: ")
if has_properly_length:
    print("Length is between 8 and 20")
if has_lower:
    print("It contains lowercase alphabet")
if has_upper:
    print("It contains uppercase alphabet")
if has_digit:
    print("It contains digit")
if has_special_character:
    print("It contains special alphabet")
if not is_in_blacklist:
    print("It does not contain blacklist passwords")

print()

# Weakness of password
print("Weakness of your password: ")
if is_short:
    print("Length is less than 8 ")
if is_long:
    print("Length is less more than 20 ")
if not has_lower:
    print("It does not contains lowercase alphabet")
if not has_upper:
    print("It does not contain uppercase alphabet")
if not has_digit:
    print("It does not contain digit")
if not has_special_character:
    print("It does not contain special alphabet")
if is_in_blacklist:
    print("It contains blacklist passwords")
