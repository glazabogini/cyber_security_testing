from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Функция шифрования
def encrypt_message(message, key): # iv можно добавить, чтобы одинаковые сообщения по-разному шифровались
    # Дополнение сообщения до длины, кратной блоку (16 байт)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    """PKCS#7 является популярным методом дополнения благодаря своей простоте и однозначности при удалении дополнения. 
    Однако выбор метода зависит от конкретных требований и контекста использования."""

    # Шифрование
    cipher = Cipher(algorithms.AES(key), modes.ECB()) # использовала ЕСВ, т.к. не реализую IV, для его реализации понадобится mode CBC(iv)
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()


# Функция расшифровки
def decrypt_message(encrypted_message, key): # iv можно добавить, чтобы одинаковые сообщения по-разному шифровались
    # Расшифровка
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_message) + decryptor.finalize()

    # Удаление дополнений
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_data) + unpadder.finalize()).decode()

# Генерация ключа AES (128 бит) и IV
def generate_aes_key():
    key = os.urandom(16)  # 16 байт = 128 бит
    #iv = os.urandom(16)   # Initialization Vector
    return key#, iv
