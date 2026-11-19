import os
import subprocess
import sys
import time
import socket
import datetime
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def ensure_test_ca():
    """Создает временный корневой сертификат для тестов на GitHub, если его нет"""
    ca_dir = os.path.join("certs", "ca")
    key_path = os.path.join(ca_dir, "rootCA.key")
    crt_path = os.path.join(ca_dir, "rootCA.crt")

    if os.path.exists(key_path) and os.path.exists(crt_path):
        return  

    os.makedirs(ca_dir, exist_ok=True)
    os.makedirs(os.path.join("certs", "hosts"), exist_ok=True)

    # Генерируем приватный ключ
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Генерируем самоподписанный корневой сертификат
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Test MITM Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def wait_for_port(host, port, timeout=10.0):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False

def test_mitm_proxy():
    # 1. Создаем тестовый CA, если запускаемся на чистом сервере GitHub
    ensure_test_ca()

    # 2. Запускаем ваш proxy_server.py
    process = subprocess.Popen(
        [sys.executable, "proxy_server.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        host = getattr(config, "PROXY_HOST", "127.0.0.1")
        if host == "0.0.0.0":
            host = "127.0.0.1"
        port = config.PROXY_PORT

        is_ready = wait_for_port(host, port, timeout=10.0)
        if not is_ready:
            out, err = process.communicate(timeout=1)
            raise RuntimeError(f"Прокси не запустился! Ошибка:\n{err}\nВывод:\n{out}")

        proxy_url = f"http://{host}:{port}"
        proxies = {"http": proxy_url, "https": proxy_url}

        def send_request(i):
            if i % 2 == 0:
                r = requests.get("https://ya.ru", proxies=proxies, verify=False, timeout=10)
                assert r.status_code == 200
            else:
                r = requests.post("https://ya.ru", data={"msg": f"test_{i}"}, proxies=proxies, verify=False, timeout=10)
                assert r.status_code in (200, 403, 405)

        with ThreadPoolExecutor(max_workers=3) as executor:
            list(executor.map(send_request, range(6)))

    finally:
        process.terminate()
        process.wait()
