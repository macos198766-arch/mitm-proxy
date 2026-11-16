import ssl
import socket
import threading
from logger import logger
from config import BYTES_SIZE, CONNECTION_TIMEOUT, READ_TIMEOUT
from generator import check

# Блокировка, чтобы два потока не перезаписывали один сертификат одновременно
cert_lock = threading.Lock()

def https_func(client_socket, host, port):
    
    remote_tls = None
    client_tls = None

    try:
        # Генерируем и загружаем сертификат
        with cert_lock:
            cert_path, key_path = check(host)

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_ctx.load_cert_chain(cert_path, key_path)
        client_ctx.set_alpn_protocols(['http/1.1'])

        # Подключаемся к реальному серверу
        raw_remote = socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT)
        server_ctx = ssl.create_default_context()
        server_ctx.set_alpn_protocols(['http/1.1'])
        remote_tls = server_ctx.wrap_socket(raw_remote, server_hostname=host)
        logger.info(f"Успешное TLS-подключение к серверу {host}:{port}")

        # Подтверждаем клиенту установку туннеля
        client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')

        # Проводим TLS-рукопожатие с клиентом
        client_tls = client_ctx.wrap_socket(client_socket, server_side=True)
        logger.info(f"TLS рукопожатие с клиентом для {host} успешно")

        def tunnel_stream(source, dest):
            try:
                source.settimeout(READ_TIMEOUT)
                while True:
                    data = source.recv(BYTES_SIZE)
                    if not data:
                        break
                    dest.sendall(data)
            except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, socket.timeout, ssl.SSLEOFError):
                # Штатное закрытие соединения одной из сторон
                pass
            except Exception as e:
                logger.debug(f"Поток туннеля {host} прерван: {e}")
            finally:
                # Как только одна сторона закрылась — закрываем оба сокета, чтобы разбудить второй поток
                for s in (client_tls, remote_tls):
                    try:
                        s.close()
                    except Exception:
                        pass

        t1 = threading.Thread(target=tunnel_stream, args=(client_tls, remote_tls), daemon=True)
        t2 = threading.Thread(target=tunnel_stream, args=(remote_tls, client_tls), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    except ssl.SSLCertVerificationError as e:
        logger.error(f"Ошибка проверки сертификата удаленного сервера {host}: {e}")
    except ssl.SSLError as e:
        logger.error(f"SSL ошибка для {host}: {e}")
    except Exception as e:
        logger.error(f"Ошибка туннеля для {host}: {e}")
    finally:
        for s in (client_tls, remote_tls):
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        logger.info(f"Туннель для {host} закрыт")
