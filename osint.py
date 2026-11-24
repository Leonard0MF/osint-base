#!/usr/bin/env python3
"""Ferramenta OSINT Básica.

Consultas simples e gratuitas a fontes públicas:
  - IP:      geolocalização, ISP, ASN (ip-api.com)
  - WHOIS:   dados de registro de domínios + resolução DNS
  - GitHub:  informações públicas de um usuário (api.github.com)

Uso interativo:   python osint.py
Uso direto:       python osint.py ip 8.8.8.8
                  python osint.py whois example.com
                  python osint.py github torvalds
                  python osint.py github torvalds --json
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import sys
from datetime import datetime

import requests

try:
    import whois  # pacote "python-whois"
except ImportError:  # o resto da ferramenta funciona mesmo sem ele
    whois = None

TIMEOUT = 10  # segundos; evita que o script trave se a API não responder
HEADERS = {"User-Agent": "osint-base/2.0"}

DOMINIO_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.[a-z]{2,63}$",
    re.IGNORECASE,
)
GITHUB_USER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$", re.IGNORECASE)


class ConsultaErro(Exception):
    """Erro esperado durante uma consulta (entrada inválida, API fora, etc.)."""


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #

def _get_json(url, **kwargs):
    """GET com timeout e mensagens de erro amigáveis."""
    try:
        r = requests.get(url, headers={**HEADERS, **kwargs.pop("headers", {})},
                         timeout=TIMEOUT, **kwargs)
    except requests.exceptions.Timeout:
        raise ConsultaErro("A API demorou demais para responder (timeout).")
    except requests.exceptions.ConnectionError:
        raise ConsultaErro("Sem conexão com a internet ou a API está fora do ar.")
    except requests.exceptions.RequestException as e:
        raise ConsultaErro(f"Erro de rede: {e}")
    return r


def _formata_data(valor):
    """python-whois às vezes devolve lista de datas; usa a primeira."""
    if isinstance(valor, list):
        valor = valor[0] if valor else None
    if isinstance(valor, datetime):
        return valor.strftime("%d/%m/%Y %H:%M")
    return valor


def _lista(valor):
    if valor is None:
        return None
    if isinstance(valor, (list, tuple, set)):
        itens = sorted({str(v).lower() for v in valor if v})
        return itens or None
    return [str(valor).lower()]


def limpa_dominio(texto):
    """Aceita 'https://www.site.com/pagina' e devolve 'www.site.com'."""
    texto = texto.strip().lower()
    texto = re.sub(r"^[a-z]+://", "", texto)
    texto = texto.split("/")[0].split("?")[0].split("#")[0]
    texto = texto.split("@")[-1].split(":")[0]
    return texto.rstrip(".")


def imprime(titulo, dados):
    print(f"\n[{titulo}]")
    largura = max(len(k) for k in dados) if dados else 0
    for chave, valor in dados.items():
        if isinstance(valor, list):
            valor = ", ".join(map(str, valor))
        if valor in (None, "", []):
            valor = "-"
        print(f"  {chave.ljust(largura)} : {valor}")


# --------------------------------------------------------------------------- #
# Consultas
# --------------------------------------------------------------------------- #

def consulta_ip(ip):
    ip = ip.strip()
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        raise ConsultaErro(f"'{ip}' não é um endereço IPv4/IPv6 válido.")
    if obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local:
        raise ConsultaErro(f"{ip} é um IP privado/reservado: não há dados públicos sobre ele.")

    campos = "status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,hosting,query"
    # Plano gratuito do ip-api só funciona via HTTP (limite: 45 requisições/min)
    r = _get_json(f"http://ip-api.com/json/{ip}", params={"fields": campos, "lang": "pt-BR"})
    if r.status_code == 429:
        raise ConsultaErro("Limite do ip-api atingido (45/min). Aguarde um pouco.")
    data = r.json()
    if data.get("status") != "success":
        raise ConsultaErro(f"Não foi possível obter dados para {ip}: {data.get('message', 'erro desconhecido')}")

    return {
        "IP": data.get("query"),
        "País": data.get("country"),
        "Região": data.get("regionName"),
        "Cidade": data.get("city"),
        "CEP": data.get("zip"),
        "Coordenadas": f"{data.get('lat')}, {data.get('lon')}" if data.get("lat") is not None else None,
        "Fuso horário": data.get("timezone"),
        "ISP": data.get("isp"),
        "Organização": data.get("org"),
        "ASN": data.get("as"),
        "DNS reverso": data.get("reverse"),
        "Rede móvel": "sim" if data.get("mobile") else "não",
        "Proxy/VPN": "sim" if data.get("proxy") else "não",
        "Hospedagem/DC": "sim" if data.get("hosting") else "não",
    }


def consulta_whois(domain):
    domain = limpa_dominio(domain)
    if not DOMINIO_RE.match(domain):
        raise ConsultaErro(f"'{domain}' não parece um domínio válido (ex: example.com).")

    resultado = {"Domínio": domain}

    # Resolução DNS (biblioteca padrão, não depende de nada externo)
    try:
        infos = socket.getaddrinfo(domain, None)
        resultado["IPs (DNS)"] = sorted({i[4][0] for i in infos})
    except socket.gaierror:
        resultado["IPs (DNS)"] = None

    if whois is None:
        resultado["WHOIS"] = "módulo não instalado (pip install python-whois)"
        return resultado

    try:
        w = whois.whois(domain)
    except Exception as e:  # python-whois lança tipos variados de exceção
        raise ConsultaErro(f"Erro na consulta WHOIS: {e}")

    if not w or not (w.get("domain_name") or w.get("creation_date")):
        raise ConsultaErro(f"Nenhum registro WHOIS encontrado para {domain}.")

    resultado.update({
        "Registrar": w.get("registrar"),
        "Registrante": w.get("registrant_name") or w.get("name") or w.get("org"),
        "País": w.get("country"),
        "Emails": _lista(w.get("emails")),
        "Criação": _formata_data(w.get("creation_date")),
        "Atualização": _formata_data(w.get("updated_date")),
        "Expiração": _formata_data(w.get("expiration_date")),
        "Name servers": _lista(w.get("name_servers")),
        "Servidor WHOIS": w.get("whois_server"),
    })
    return resultado


def busca_github_username(username):
    username = username.strip().lstrip("@")
    if not GITHUB_USER_RE.match(username):
        raise ConsultaErro(f"'{username}' não é um username válido do GitHub.")

    headers = {"Accept": "application/vnd.github+json"}
    # Opcional: um token aumenta o limite de 60 para 5000 requisições/hora
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    r = _get_json(f"https://api.github.com/users/{username}", headers=headers)
    if r.status_code == 404:
        raise ConsultaErro(f"Usuário '{username}' não encontrado no GitHub.")
    if r.status_code in (403, 429):
        reset = r.headers.get("X-RateLimit-Reset")
        quando = datetime.fromtimestamp(int(reset)).strftime("%H:%M") if reset else "mais tarde"
        raise ConsultaErro(f"Limite da API do GitHub atingido. Tente novamente às {quando} "
                           "ou defina a variável GITHUB_TOKEN.")
    if r.status_code != 200:
        raise ConsultaErro(f"GitHub respondeu com status {r.status_code}.")

    data = r.json()
    criado = data.get("created_at")
    if criado:
        criado = datetime.strptime(criado, "%Y-%m-%dT%H:%M:%SZ").strftime("%d/%m/%Y")

    return {
        "Usuário": data.get("login"),
        "ID": data.get("id"),
        "Tipo": data.get("type"),
        "Nome": data.get("name"),
        "Bio": data.get("bio"),
        "Empresa": data.get("company"),
        "Localização": data.get("location"),
        "Email público": data.get("email"),
        "Blog/site": data.get("blog"),
        "Twitter/X": data.get("twitter_username"),
        "Repositórios públicos": data.get("public_repos"),
        "Gists públicos": data.get("public_gists"),
        "Seguidores": data.get("followers"),
        "Seguindo": data.get("following"),
        "Conta criada em": criado,
        "Perfil": data.get("html_url"),
    }


CONSULTAS = {
    "ip": ("IP", consulta_ip, "Digite o IP: "),
    "whois": ("WHOIS", consulta_whois, "Digite o domínio (ex: example.com): "),
    "github": ("GitHub", busca_github_username, "Digite o username do GitHub: "),
}


# --------------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------------- #

def executa(tipo, alvo, como_json=False):
    titulo, funcao, _ = CONSULTAS[tipo]
    try:
        dados = funcao(alvo)
    except ConsultaErro as e:
        print(f"[!] {e}", file=sys.stderr)
        return False
    if como_json:
        print(json.dumps(dados, ensure_ascii=False, indent=2, default=str))
    else:
        imprime(titulo, dados)
    return True


def menu():
    opcoes = {"1": "ip", "2": "whois", "3": "github"}
    while True:
        print("\n=== Ferramenta OSINT Básica Grátis ===")
        print("1 - Consulta IP")
        print("2 - Consulta WHOIS domínio")
        print("3 - Busca usuário GitHub")
        print("0 - Sair")
        escolha = input("Escolha uma opção: ").strip()

        if escolha in ("0", "q", "sair"):
            break
        tipo = opcoes.get(escolha)
        if not tipo:
            print("Opção inválida.")
            continue
        alvo = input(CONSULTAS[tipo][2]).strip()
        if not alvo:
            print("Nada digitado.")
            continue
        executa(tipo, alvo)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Ferramenta OSINT básica e gratuita.")
    parser.add_argument("tipo", nargs="?", choices=CONSULTAS, help="tipo de consulta")
    parser.add_argument("alvo", nargs="?", help="IP, domínio ou username")
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    args = parser.parse_args(argv)

    if args.tipo and not args.alvo:
        parser.error("informe o alvo da consulta")

    try:
        if args.tipo:
            return 0 if executa(args.tipo, args.alvo, args.json) else 1
        menu()
    except (KeyboardInterrupt, EOFError):
        print("\nSaindo...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
