import os
import socket
import sys
import select
import errno
from AES import generate_aes_key, encrypt_message, decrypt_message  # Импорт функций из модуля AES
from RSA import generate_rsa_keypair, encrypt_with_rsa, decrypt_with_rsa # Импорт функций из модуля RSA

HEADER_LENGTH = 10

IP = "127.0.0.1"
PORT = 1234
my_username = input("Username: ") # желательно "жопик"

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

# Добавляем выбор метода шифрования
encryption_method = input("Choose encryption method (AES/RSA): ").strip().upper()

if encryption_method == "RSA":
    # Генерируем пару RSA-ключей
    private_key, public_key = generate_rsa_keypair()

    # Отправляем свой публичный ключ
    print(f"Your RSA Public Key (share this): {public_key.decode()}")
    print(f"Your RSA Private Key (keep this secure): {private_key.decode()}")

    # Определяем, какой файл использовать для своего публичного ключа
    my_key_file = "user1_key"

    # Ключ второго пользователя
    other_key_file = "user2_key"

    # Удаляем старые файлы, если они существуют
    try:
        os.remove(my_key_file)
    except FileNotFoundError:
        pass  # Файл отсутствует — ничего не делаем

    try:
        os.remove(other_key_file)
    except FileNotFoundError:
        pass  # Файл отсутствует — ничего не делаем

    # Сохраняем свой публичный ключ в файл
    with open(my_key_file, "wb") as file:
        file.write(public_key)
    print(f"Your RSA Public Key has been saved to {my_key_file}")

    # Ждем, пока другой пользователь создаст свой ключ
    print(f"Waiting for the other user's key in {other_key_file}...")
    while True:
        try:
            with open(other_key_file, "rb") as file:
                other_public_key = file.read()
            print(f"Successfully loaded the RSA Public Key from {other_key_file}")
            break
        except FileNotFoundError:
            pass  # Ждем появления файла

else:
    # Генерируем AES ключ

    AES_KEY = generate_aes_key() # можно добавить IV
    print(f"Your AES Key (keep secure): {AES_KEY.hex()}")
    #print(f"Your AES IV: {IV.hex()}")

while True:

    # Wait for user to input a message
    message = input(f'{my_username} > ')

    # If message is not empty - send it
    if message:

        if encryption_method == "AES":
            # Шифруем сообщение с использованием AES
            encrypted_message = encrypt_message(message, AES_KEY) # можно добавить IV
            encrypted_message_hex = encrypted_message.hex()

        elif encryption_method == "RSA":
            # Шифруем сообщение с использованием RSA
            encrypted_message = encrypt_with_rsa(message.encode('utf-8'), other_public_key)
            encrypted_message_hex = encrypted_message.hex()

        message_header = f"{len(encrypted_message_hex):<{HEADER_LENGTH}}".encode('utf-8')
        client_socket.send(message_header + encrypted_message_hex.encode('utf-8'))


        """Чтобы обеспечить корректную передачу зашифрованных данных, их часто преобразуют в шестнадцатеричный формат. 
        Это процесс, при котором каждый байт данных представляется двумя символами из набора [0-9, A-F], 
        что делает данные пригодными для текстовой передачи."""

    try:
        # Now we want to loop over received messages (there might be more than one) and print them
        while True:

            # Receive our "header" containing username length, it's size is defined and constant
            username_header = client_socket.recv(HEADER_LENGTH)

            # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
            if not len(username_header):
                print('Connection closed by the server')
                sys.exit()

            # Convert header to int value
            username_length = int(username_header.decode('utf-8').strip())

            # Receive and decode username
            username = client_socket.recv(username_length).decode('utf-8')

            # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
            message_header = client_socket.recv(HEADER_LENGTH)
            message_length = int(message_header.decode('utf-8').strip())
            encrypted_message_hex = client_socket.recv(message_length).decode('utf-8')

            # Конвертируем hex обратно в бинарные данные
            encrypted_message = bytes.fromhex(encrypted_message_hex)

            if encryption_method == "AES":
                # Расшифровываем сообщение с использованием AES
                decrypted_message = decrypt_message(encrypted_message, AES_KEY) # можно добавить IV

            elif encryption_method == "RSA":
                # Расшифровываем сообщение с использованием RSA
                decrypted_message = decrypt_with_rsa(encrypted_message, private_key).decode('utf-8')


            # Print message
            print(f'{username} > {decrypted_message}')

    except IOError as e:
        # This is normal on non blocking connections - when there are no incoming data error is going to be raised
        # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
        # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
        # If we got different error code - something happened
        if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
            print('Reading error: {}'.format(str(e)))
            sys.exit()

        # We just did not receive anything
        continue

    except Exception as e:
        # Any other exception - something happened, exit
        print('Reading error: '.format(str(e)))
        sys.exit()