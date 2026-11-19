import subprocess
import sys
import time
import socket
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
                # Проверка GET-запроса через HTTPS (CONNECT + TLS)
                r = requests.get("https://ya.ru", proxies=proxies, verify=False, timeout=10)
                assert r.status_code == 200
            else:
                # Проверка POST-запроса и передачи данных через HTTPS
                r = requests.post("https://ya.ru", data={"msg": f"test_{i}"}, proxies=proxies, verify=False, timeout=10)
                # Если ответ получен (не таймаут и не ошибка прокси), значит TLS-туннель и POST сработали
                assert r.status_code in (200, 403, 405)


        # Проверяем сразу 6 параллельных запросов в 3 потока
        with ThreadPoolExecutor(max_workers=3) as executor:
            list(executor.map(send_request, range(6)))

    finally:
        process.terminate()
        process.wait()
