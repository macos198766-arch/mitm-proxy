import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("certs/ca", exist_ok=True)

def create_root_ca(
    common_name: str = "My Proxy Root CA",
    key_path: str = "certs/ca/rootCA.key",
    cert_path: str = "certs/ca/rootCA.crt",
    key_size: int = 4096,
    valid_days: int = 3650,          # 10 лет
    country: str = "RU",
    org: str = "My Org",
):
    # 1. Приватный ключ (RSA 4096)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # 2. Subject и Issuer (для самоподписанного они совпадают)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.now(timezone.utc)

    # 3. Сам сертификат
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))   # запас на рассинхрон часов
        .not_valid_after(now + timedelta(days=valid_days))
        # Ключевые расширения для CA:
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,     
                crl_sign=True,           
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    # 4. Сохраняем ключ (без пароля — для прокси удобно; для прода — с паролем)
    key_path = Path(key_path)
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # или PKCS8
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)   # только владелец

    # 5. Сохраняем сертификат
    Path(cert_path).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )

    print(f"CA ключ:  {key_path}")
    print(f"CA серт:  {cert_path}")
    return private_key, cert


if __name__ == "__main__":
    create_root_ca()