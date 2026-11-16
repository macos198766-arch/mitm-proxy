import socket
from logger import logger
from request_parse import get_address
from config import BYTES_SIZE, CONNECTION_TIMEOUT, READ_TIMEOUT

def http_func(client_socket, host, port, modified_request):
    
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
