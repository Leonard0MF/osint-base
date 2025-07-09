import requests
import whois

def consulta_ip(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        r = requests.get(url)
        data = r.json()
        if data['status'] == 'success':
            print(f"[IP] {ip} - {data['country']}, {data['regionName']}, {data['city']}")
            print(f"ISP: {data['isp']}")
        else:
            print(f"Não foi possível obter dados para o IP {ip}")
    except Exception as e:
        print(f"Erro ao consultar IP: {e}")

def consulta_whois(domain):
    try:
        w = whois.whois(domain)
        print(f"[WHOIS] Domínio: {domain}")
        print(f"Registrante: {w.get('registrant_name')}")
        print(f"Email: {w.get('emails')}")
        print(f"Data criação: {w.get('creation_date')}")
        print(f"Data expiração: {w.get('expiration_date')}")
        print(f"Servidor WHOIS: {w.get('whois_server')}")
    except Exception as e:
        print(f"Erro na consulta WHOIS: {e}")

def busca_github_username(username):
    url = f"https://api.github.com/users/{username}"
    try:
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()
            print(f"[GitHub] Usuário: {data['login']}")
            print(f"Nome: {data.get('name')}")
            print(f"Bio: {data.get('bio')}")
            print(f"Localização: {data.get('location')}")
            print(f"Repositórios públicos: {data.get('public_repos')}")
        else:
            print(f"Usuário '{username}' não encontrado no GitHub.")
    except Exception as e:
        print(f"Erro na consulta GitHub: {e}")

def main():
    print("=== Ferramenta OSINT Básica Grátis ===")
    print("1 - Consulta IP")
    print("2 - Consulta WHOIS domínio")
    print("3 - Busca usuário GitHub")
    escolha = input("Escolha uma opção: ").strip()

    if escolha == "1":
        ip = input("Digite o IP: ").strip()
        consulta_ip(ip)
    elif escolha == "2":
        domain = input("Digite o domínio (ex: example.com): ").strip()
        consulta_whois(domain)
    elif escolha == "3":
        username = input("Digite o username do GitHub: ").strip()
        busca_github_username(username)
    else:
        print("Opção inválida.")

if __name__ == "__main__":
    main()
input("\nPressione Enter para sair...")
