import os
import datetime
import threading
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from logger import logger
from config import VALID_TIME

# Глобальная блокировка для защиты от одновременной генерации одного домена
_gen_lock = threading.Lock()

# Загружаем корневой CA один раз при импорте модуля, чтобы не читать диск при каждом запросе
with open("certs/ca/rootCA.key", "rb") as f:
    _CA_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open("certs/ca/rootCA.crt", "rb") as f:
    _CA_CERT = x509.load_pem_x509_certificate(f.read())

def check(domain):
    # Защита от символов, запрещенных в именах файлов (на всякий случай)
    safe_domain = domain.replace(":", "_")
    cert_path = f"certs/{safe_domain}.crt"
    key_path = f"certs/{safe_domain}.key"

    with _gen_lock:
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path
        return cert_gen(domain, cert_path, key_path)

def cert_gen(domain, cert_path, key_path):
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    # Используем timezone-aware UTC и делаем запас -1 день на случай расхождения часов
    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = now - datetime.timedelta(days=1)
    not_valid_after = now + datetime.timedelta(days=VALID_TIME)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(_CA_CERT.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(_CA_KEY, hashes.SHA256())
    )

    # Сначала пишем во временные файлы, затем атомарно переименовываем
    tmp_cert = f"{cert_path}.tmp"
    tmp_key = f"{key_path}.tmp"

    with open(tmp_cert, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with open(tmp_key, "wb") as f:
        f.write(leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    os.replace(tmp_cert, cert_path)
    os.replace(tmp_key, key_path)

    logger.info(f"Создан сертификат для {domain}")
    return cert_path, key_path
