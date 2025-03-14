
import requests
import os
import sys
import time
import json

# Configurações
BASE_URL = os.getenv("BASE_URL","https://api-scents.onrender.com")
USERNAME = os.getenv("API_USERNAME", "jenifer")
PASSWORD = os.getenv("API_PASSWORD", "kjcd5588J#")
FILE_PATH = "A5CBR.mp3"  # Arquivo de teste

def check_server():
    """Verifica se o servidor está rodando"""
    global BASE_URL
    urls_to_try = [
        BASE_URL,
        "http://localhost:3004",
        "http://127.0.0.1:3004"
    ]
    
    for url in urls_to_try:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                BASE_URL = url.rstrip("/")
                print(f"Servidor online: {BASE_URL}")
                return True
        except requests.exceptions.RequestException:
            print(f"Não foi possível conectar ao servidor: {url}")
    
    print("Nenhum servidor encontrado.")
    return False

def make_request(method, endpoint, token=None, **kwargs):
    """Executa requisições HTTP com segurança"""
    url = f"{BASE_URL}{endpoint}"
    headers = kwargs.pop("headers", {})
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        response = requests.request(method, url, headers=headers, timeout=10, verify=True, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        print(f"Erro HTTP {response.status_code}: {response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão: {e}")
        return None

def register(username, password):
    """Registra um novo usuário"""
    print(f"\n=== REGISTRANDO USUÁRIO ===")
    print(f"Username: {username}")
    result = make_request("post", "/register", json={"username": username, "password": password})
    if result:
        print(f"Resultado: {json.dumps(result, indent=2)}")
    return result

def login(username, password):
    """Realiza login e retorna um token JWT"""
    print(f"\n=== LOGIN DO USUÁRIO ===")
    print(f"Username: {username}")
    result = make_request("post", "/login", data={"username": username, "password": password, "grant_type": "password"})
    if result:
        print(f"Token de acesso: {result.get('access_token')}")
    return result.get("access_token") if result else None

def upload_ad(token, file_path):
    """Faz upload de um anúncio (MP4 ou MP3)"""
    print(f"\n=== UPLOAD DE ARQUIVO ===")
    print(f"Arquivo: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"ERRO: Arquivo não encontrado: {file_path}")
        return None

    file_size = os.path.getsize(file_path) / 1024  # KB
    print(f"Tamanho: {file_size:.2f} KB")

    with open(file_path, "rb") as file:
        result = make_request("post", "/upload", token=token, files={"file": file})

    if result:
        print(f"Resultado: {json.dumps(result, indent=2)}")
        print(f"ID do anúncio: {result.get('ad_id')}")
    return result.get("ad_id") if result else None

def apply_scents(token, ad_id):
    """Aplica Scents ao anúncio"""
    print(f"\n=== APLICANDO SCENTS ===")
    print(f"ID do anúncio: {ad_id}")
    result = make_request("post", f"/apply-scents/{ad_id}", token=token)
    if result:
        print(f"Resultado: {json.dumps(result, indent=2)}")
    return result

def get_ad(ad_id):
    """Obtém informações sobre o anúncio"""
    print(f"\n=== INFORMAÇÕES DO ANÚNCIO ===")
    print(f"ID do anúncio: {ad_id}")
    result = make_request("get", f"/ad/{ad_id}")
    if result:
        print(f"Resultado: {json.dumps(result, indent=2)}")
    return result

def get_stats(token, ad_id):
    """Obtém estatísticas do anúncio"""
    print(f"\n=== ESTATÍSTICAS DO ANÚNCIO ===")
    print(f"ID do anúncio: {ad_id}")
    result = make_request("get", f"/stats/{ad_id}", token=token)
    if result:
        print(f"Resultado: {json.dumps(result, indent=2)}")
    return result

def print_summary(username, token, file_path, ad_id, stats):
    """Imprime um resumo das informações"""
    print("\n" + "="*50)
    print("             RESUMO DO TESTE              ")
    print("="*50)
    print(f"Usuário:     {username}")
    print(f"Token:       {token[:20]}... (truncado)")
    print(f"Arquivo:     {file_path}")
    print(f"ID Anúncio:  {ad_id}")
    if stats:
        print(f"Visualizações: {stats.get('views', 0)}")
    print("="*50)

if __name__ == "__main__":
    # Verifica se o servidor está ativo
    if not check_server():
        sys.exit(1)

    print(f"Arquivo de teste: {FILE_PATH} (existe: {os.path.exists(FILE_PATH)})")

    # Fluxo de testes
    register(USERNAME, PASSWORD)
    jwt_token = login(USERNAME, PASSWORD)

    if jwt_token:
        ad_id = upload_ad(jwt_token, FILE_PATH)
        if ad_id:
            apply_scents(jwt_token, ad_id)
            get_ad(ad_id)
            stats = get_stats(jwt_token, ad_id)
            
            # Imprime um resumo das informações
            print_summary(USERNAME, jwt_token, FILE_PATH, ad_id, stats)
    else:
        print("Falha ao obter token, encerrando testes.")
