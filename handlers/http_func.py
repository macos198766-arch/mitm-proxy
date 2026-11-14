import socket
from logger import logger
from config import BYTES_SIZE, CONNECTION_TIMEOUT, READ_TIMEOUT

def http_func(client_socket, request, url):
    # Убираем префикс http://
    clean_url = url[7:] if url.startswith("http://") else url

    # Разделяем хост и путь запроса
    if '/' in clean_url:
        host_port, path = clean_url.split('/', 1)
        path = '/' + path
    else:
        host_port = clean_url
        path = '/'

    # Определяем хост и порт
    port = 80
    if ':' in host_port:
        host, port_str = host_port.split(':', 1)
        port = int(port_str)
    else:
        host = host_port

    # Заменяем полный URL в первой строке на относительный путь
    lines = request.split(b'\r\n')
    first_line_parts = lines[0].split(b' ')
    if len(first_line_parts) >= 3:
        first_line_parts[1] = path.encode('utf-8')
        lines[0] = b' '.join(first_line_parts)
    
    modified_request = b'\r\n'.join(lines)
    # Меняем заголовок прокси на закрытие соединения после ответа
    modified_request = modified_request.replace(b"Proxy-Connection: keep-alive", b"Connection: close")
    modified_request = modified_request.replace(b"Connection: keep-alive", b"Connection: close")

    # Открытие сокета вынесено на основной уровень функции
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as remote_socket:
        remote_socket.settimeout(CONNECTION_TIMEOUT)
        try:
            remote_socket.connect((host, port))
            remote_socket.settimeout(READ_TIMEOUT)
            remote_socket.sendall(modified_request)
            logger.info(f"Успешное подключение и отправка сообщения на {host}:{port}")
        except Exception as e:
            logger.error(f'Ошибка при подключении к {host}: {e}')
            return

        while True:
            try:
                response = remote_socket.recv(BYTES_SIZE)
                if not response:
                    break
                client_socket.sendall(response)
            except Exception as e:
                logger.error(f'Ошибка при передаче ответа пользователю: {e}')
                break
