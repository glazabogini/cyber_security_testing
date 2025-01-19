from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

# Генерация ключей RSA
def generate_rsa_keypair():
    # Генерация пары ключей RSA: приватного и публичного.
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Функция шифрования
def encrypt_with_rsa(message, public_key):
    # Шифрование сообщения с использованием публичного ключа RSA.
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(message)

# Функция расшифровки
def decrypt_with_rsa(encrypted_message, private_key):
    # Расшифровка сообщения с использованием приватного ключа RSA.
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(encrypted_message)

"""я использовала другую библиотеку для работы с RSA, т.к. она проще в использовании 
и не требует работы с ключами в PEM формате (текстовый формат ключей), а делает это автоматически

для ее работы нужно установить pip install pycryptodomex"""



