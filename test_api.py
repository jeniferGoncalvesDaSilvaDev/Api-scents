import requests

# URL da sua API
BASE_URL = "https://api-scents.onrender.com"

# Testando a rota principal
response = requests.get(BASE_URL)

# Exibir o status e resposta
print(f"Status Code: {response.status_code}")
print("Response JSON:", response.json() if response.headers.get("Content-Type") == "application/json" else response.text)