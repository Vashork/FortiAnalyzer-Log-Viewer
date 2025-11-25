from config import *
from client.faz_client import FortiAnalyzerClient

client = FortiAnalyzerClient(
    url=FORTIANALYZER_URL,
    username=FORTIANALYZER_USERNAME,
    password=FORTIANALYZER_PASSWORD,
)

client.login()

payload = {
    "id": "123456789",
    "jsonrpc": "2.0",
    "method": "get",
    "params": [
        {
            "apiver": 3,
            "url": "/logview/adom/root",
        }
    ],
    "session": client.session
}

print(client._post(payload))

client.logout()
