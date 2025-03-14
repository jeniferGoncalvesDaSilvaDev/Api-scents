import requests

# Defina a URL base da API
BASE_URL = "https://api-scents.onrender.com"

# Credenciais para login
username = "jenifer"
password = "kjcd5588"

# Autenticação - Obter Token JWT
auth_response = requests.post(f"{BASE_URL}/login", json={"username": username, "password": password})

if auth_response.status_code == 200:
    token = auth_response.json().get("token")
    headers = {"Authorization": f"Bearer {token}"}

    # Defina o ID do anúncio que deseja consultar
    ad_id = "1"

    # Requisição para obter estatísticas do anúncio
    stats_response = requests.get(f"{BASE_URL}/stats/{ad_id}", headers=headers)

    if stats_response.status_code == 200:
        print("Estatísticas do Anúncio:")
        print(stats_response.json())
    else:
        print("Erro ao obter estatísticas:", stats_response.text)
else:
    print("Erro na autenticação:", auth_response.text)