import h11
from urllib.parse import urlparse, urlsplit

def get_address(raw_request):
    conn = h11.Connection(our_role=h11.SERVER)
    conn.receive_data(raw_request)
    event = conn.next_event()

    method = event.method.decode('utf-8')
    request = raw_request.decode('utf-8')
    lines = request.split('\r\n')
    first_line = lines[0].split(' ')
    url = first_line[1]

    if method == 'CONNECT':
        parsed = urlsplit("//" + url)
        host = parsed.hostname
        port = parsed.port or 443
        return host, port
    else:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 80
        path = parsed.path

        if parsed.query:
            path += '?' + parsed.query
    
        lines[0] = f"{method} {path} HTTP/1.1"
        modified_request = '\r\n'.join(lines).encode('utf-8')

        # Меняем заголовок прокси на закрытие соединения после ответа
        modified_request = modified_request.replace(b"Proxy-Connection: keep-alive", b"Connection: close")
        modified_request = modified_request.replace(b"Connection: keep-alive", b"Connection: close")

        return host, port, modified_request