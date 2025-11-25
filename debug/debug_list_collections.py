from config import *
from client.faz_client import FortiAnalyzerClient

client = FortiAnalyzerClient(
    url=FORTIANALYZER_URL,
    username=FORTIANALYZER_USERNAME,
    password=FORTIANALYZER_PASSWORD,
)

client.login()

# 1. Смотрим все root-узлы API
payload = {
    "id": 1,
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "url": "/",
        }
    ],
    "session": client.session
}
print("ROOT / :", client._post(payload))

# 2. Смотрим все коллекции logdb
payload = {
    "id": 2,
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "url": "/logdb",
        }
    ],
    "session": client.session
}
print("\n/logdb :", client._post(payload))

# 3. Смотрим traffic root
payload = {
    "id": 3,
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "url": "/logdb/traffic",
        }
    ],
    "session": client.session
}
print("\n/logdb/traffic :", client._post(payload))

# 4. Проверяем “search”
payload = {
    "id": 4,
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "url": "/logdb/traffic/logsearch",
        }
    ],
    "session": client.session
}
print("\n/logdb/traffic/logsearch :", client._post(payload))

client.logout()
