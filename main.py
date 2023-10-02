import subprocess
import random
import socket
import re

# Порты для клиента, сервера и подсчета голосов
CLIENT_PORT = 3000
SERVER_PORT = 4000
SERVER_COUNT_PORT = 5000
PRIVATE_KEY_NAME = "privatekey.pem"
PUBLIC_KEY_NAME = "publickey.pem"

# Функция для извлечения информации о ключе RSA
def parse_rsa_key_info(public_output, private_output):
    for _ in range(2):
        match = re.search("modulus:\s+([\s\S]+?)publicExponent:", public_output)
        if match:
            modulus = int(match.group(1).replace(":", "").replace(" ", "").replace("\r\n", ""), 16)
        match = re.search("publicExponent:\s+([\s\S]+?)privateExponent:", public_output)
        if match:
            public_exponent = int(match.group(1).replace(":", "").replace(" ", "").replace("\r\n", "").replace("(0x10001)", ""))
        match = re.search("privateExponent:\s+([\s\S]+?)prime1:", public_output)
        if match:
            private_exponent = int(match.group(1).replace(":", "").replace(" ", "").replace("\r\n", ""), 16)
        public_output = private_output
    return modulus, public_exponent, private_exponent

# Функция для вычисления модульной степени
def modular_power(base_value, exponent, modulus):
    result = 1
    while exponent:
        if exponent % 2 == 1:
            result = (result * base_value) % modulus
        base_value = (base_value * base_value) % modulus
        exponent //= 2
    return result

# Функция для вычисления модульного обратного значения
def modular_inverse(a, n):
    m0 = n
    y = 0
    x = 1

    if n == 1:
        return 0

    while a > 1:
        q = a // n
        t = n

        n = a % n
        a = t
        t = y

        y = x - q * y
        x = t

    if x < 0:
        x += m0
    return x

# Функция для нахождения наибольшего общего делителя
def greatest_common_divisor(a, b):
    while b:
        a, b = b, a % b
    return a

# Функция для проверки взаимной простоты
def is_coprime(a, b):
    return greatest_common_divisor(a, b) == 1

# Функция для генерации затемняющего множителя
def generate_blinding_factor(modulus):
    value = random.randint(0, modulus)
    while not is_coprime(value, modulus):
        value = random.randint(0, modulus)
    return value

# Функция для отправки сообщения
def send_message(message: int):
    subprocess.run(
        "openssl genpkey -algorithm RSA -out {} -pkeyopt rsa_keygen_bits:1024".format(PRIVATE_KEY_NAME), shell=True)
    subprocess.run("openssl rsa -pubout -in {} -out {}".format(PRIVATE_KEY_NAME, PUBLIC_KEY_NAME), shell=True)
    private_key_output = subprocess.check_output("openssl rsa -in {} -noout -text".format(PRIVATE_KEY_NAME),
                                                 shell=True)
    public_key_output = subprocess.check_output("openssl rsa -pubin -in {} -noout -text".format(PUBLIC_KEY_NAME),
                                                shell=True)

    modulus, public_exponent, private_exponent = parse_rsa_key_info(str(public_key_output.decode("UTF-8")),
                                                                    str(private_key_output.decode("UTF-8")))

    blinding_factor_int = generate_blinding_factor(modulus)
    blinded_message = message * modular_power(blinding_factor_int, public_exponent, modulus)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', SERVER_PORT))
        s.sendall(str(blinded_message).encode('utf-8'))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as response:
        response.bind(('localhost', CLIENT_PORT))
        response.listen(1)
        conn, addr = response.accept()
        data = conn.recv(1024)
        blinded_signature = int(data.decode('utf-8'))

    unblinded_signature = modular_inverse(blinding_factor_int, modulus) * blinded_signature % modulus

    if modular_power(unblinded_signature, public_exponent, modulus) == message:
        print("Подпись получена")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', SERVER_COUNT_PORT))
            s.sendall(str(message).encode('utf-8'))
    else:
        print("Ошибка!")

# Основной цикл программы
while True:
    try:
        input_text = input("\nВведите номер кандидата (от 1 до 5) или 'q' для выхода: ")
        if input_text == 'q':
            print("Голосование завершено.")
            break
        input_number = int(input_text)
        if 1 <= input_number <= 5:
            send_message(input_number)
        else:
            print("Пожалуйста, введите число от 1 до 5.")
    except ValueError:
        print("Введите целое число!")
