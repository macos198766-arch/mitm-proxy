from handlers.http_func import http_func
from handlers.https_func import https_func
from logger import logger
from request_parse import get_address
from config import BYTES_SIZE, READ_TIMEOUT

def handle_client(client_socket, address):
    with client_socket:
        client_socket.settimeout(READ_TIMEOUT)
        try:
            raw_request = client_socket.recv(BYTES_SIZE)
            logger.info(f"Запрос от клиента({address})")
            if not raw_request:
                return
        except Exception as e:
            logger.error(f"Ошибка при запросе от клиента: {e}")
            return
        try:
            result = get_address(raw_request)
        except Exception as e:
            logger.error(f"Ошибка парсинга: {e}")
            return
        if len(result) == 2:
            host, port = result
            https_func(client_socket, host, port)
        else:
            host, port, modified_request = result
            http_func(client_socket, host, port, modified_request)

    logger.info("Закрытие соединения")