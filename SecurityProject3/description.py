# نقد و توضیحات کد:

# کتابخانه‌های استفاده شده:
import argparse  # برای پردازش خط فرمان
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # برای ایجاد کلید مشتق شده
from cryptography.hazmat.backends import default_backend  # برای انتخاب پشتیبان متد اجرای کریپتوگرافی
from cryptography.hazmat.primitives import hashes  # برای استفاده از توابع هش
from base64 import urlsafe_b64encode, urlsafe_b64decode  # برای انجام عملیات Base64
import os  # برای ایجاد اعداد تصادفی و تولید نمونه از فایل‌ها


# کلاس PasswordManager:
class PasswordManager:
    """
    کلاس PasswordManager برای مدیریت گذرواژه‌های رمزنگاری شده است.
    """

    def __init__(self, key):
        """
        متد ابتدایی برای ایجاد یک نمونه از کلاس PasswordManager.

        پارامترها:
        - key (str): کلید اصلی برای رمزنگاری و رمزگشایی گذرواژه.
        """
        self.key = key

    def encrypt_password(self, password):
        """
        رمزنگاری یک گذرواژه با استفاده از مشتق‌کننده کلید PBKDF2 و رمزنگاری AES.

        پارامترها:
        - password (str): گذرواژه‌ای که باید رمزنگاری شود.

        بازگشت:
        - str: گذرواژه رمزنگاری شده.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            iterations=100000,
            backend=default_backend()
        )
        key = urlsafe_b64encode(kdf.derive(self.key.encode()))
        cipher_text = urlsafe_b64encode(password.encode())
        return key + cipher_text

    def decrypt_password(self, encrypted_password):
        """
        رمزگشایی یک گذرواژه رمزنگاری شده با استفاده از کلید اصلی.

        پارامترها:
        - encrypted_password (str): گذرواژه رمزنگاری شده.

        بازگشت:
        - str: گذرواژه رمزگشایی شده.
        """
        key = urlsafe_b64encode(self.key.encode())
        cipher_text = urlsafe_b64decode(encrypted_password)
        return urlsafe_b64decode(cipher_text[len(key):]).decode()

    def save_password(self, name, comment, password):
        """
        ذخیره یک ورودی گذرواژه جدید در یک فایل متنی.

        پارامترها:
        - name (str): نام مرتبط با گذرواژه.
        - comment (str): یک نظر یا توضیح برای گذرواژه.
        - password (str): گذرواژه برای ذخیره.
        """
        encrypted_password = self.encrypt_password(password)
        with open('passwords.txt', 'a') as file:
            file.write(f"{name}:{comment}:{encrypted_password}\n")

    @staticmethod
    def show_passwords():
        """
        نمایش تمام گذرواژه‌های ذخیره شده در فایل متنی.
        """
        with open('passwords.txt', 'r') as file:
            for line in file:
                name, comment, _ = line.strip().split(':')
                print(f"Name: {name}, Comment: {comment}")

    def show_password(self, name):
        """
        نمایش جزئیات یک گذرواژه خاص.

        پارامترها:
        - name (str): نام مرتبط با گذرواژه.
        """
        with open('passwords.txt', 'r') as file:
            for line in file:
                data = line.strip().split(':')
                if data[0] == name:
                    decrypted_password = self.decrypt_password(data[2])
                    print(f"Name: {data[0]}, Comment: {data[1]}, Password: {decrypted_password}")

    def update_password(self, name, new_password):
        """
        به‌روزرسانی گذرواژه یک ورودی خاص.

        پارامترها:
        - name (str): نام مرتبط با گذرواژه.
        - new_password (str): گذرواژه جدید برای به‌روزرسانی.
        """
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        with open('passwords.txt', 'w') as file:
            for line in lines:
                data = line.strip().split(':')
                if data[0] == name:
                    updated_line = f"{name}:{data[1]}:{self.encrypt_password(new_password).decode()}\n"
                    file.write(updated_line)
                else:
                    file.write(line)

    @staticmethod
    def delete_password(names):
        """
        حذف ورودی‌های گذرواژه برای نام‌های مشخص شده.

        پارامترها:
        - names (list): لیستی از نام‌ها برای حذف گذرواژه‌ها.
        """
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        with open('passwords.txt', 'w') as file:
            for line in lines:
                data = line.strip().split(':')
                if data[0] not in names:
                    file.write(line)


def main():
    """
    تابع اصلی برای انجام عملیات رابط خط فرمان.
    """
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    parser.add_argument("--newpass", help="Create a new password", nargs=3)
    parser.add_argument("--showpass", help="Show all passwords", action="store_true")
    parser.add_argument("--sel", help="Show a specific password", nargs=1)
    parser.add_argument("--update", help="Update a password", nargs=1)
    parser.add_argument("--delete", help="Delete a password", nargs='+')  # Allow one or more names

    args = parser.parse_args()

    key = input("Enter your master password: ")
    password_manager = PasswordManager(key)

    if args.newpass:
        name, comment, user_password = args.newpass
        password_manager.save_password(name, comment, user_password)
    elif args.showpass:
        password_manager.show_passwords()
    elif args.sel:
        name = args.sel[0]
        password_manager.show_password(name)
    elif args.update:
        name = args.update[0]
        new_password = input("Enter the new password: ")
        password_manager.update_password(name, new_password)
    elif args.delete:
        names = args.delete
        password_manager.delete_password(names)
    else:
        print("Invalid command. Use --help for usage information.")


if __name__ == "__main__":
    main()
