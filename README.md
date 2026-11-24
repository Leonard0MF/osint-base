# Ferramenta OSINT Básica

Script em Python que faz consultas simples e gratuitas para ajudar na coleta de informações públicas (OSINT).

Você pode:

- **IP** – geolocalização, ISP, ASN, DNS reverso e se o IP é de proxy/VPN ou datacenter
- **WHOIS** – registrar, datas de criação/expiração, name servers, emails e IPs do domínio (DNS)
- **GitHub** – nome, bio, empresa, localização, seguidores, repositórios e data de criação da conta

## Como usar

1. Tenha o Python 3.8+ instalado (eu usei o 3.14).
2. Clone o repositório:
   ```bash
   git clone https://github.com/Leonard0MF/osint-base.git
   cd osint-base
   ```
3. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```
   > Atenção: o pacote de WHOIS é o `python-whois`, **não** o `whois`.
4. Rode o script:
   ```bash
   python osint.py
   ```
5. Escolha a opção no menu e digite os dados. Use `0` para sair.

### Modo direto (linha de comando)

```bash
python osint.py ip 8.8.8.8
python osint.py whois example.com
python osint.py whois https://www.example.com/pagina   # a URL é limpa automaticamente
python osint.py github torvalds
python osint.py github torvalds --json                  # saída em JSON
```

### Limite da API do GitHub (opcional)

Sem autenticação, o GitHub permite 60 consultas por hora. Para subir para 5000, crie um
[token pessoal](https://github.com/settings/tokens) (sem nenhuma permissão marcada) e defina:

```bash
export GITHUB_TOKEN=seu_token        # Linux/macOS
set GITHUB_TOKEN=seu_token           # Windows (cmd)
```

### Testes

```bash
python -m unittest -v
```

Os testes não usam a internet: as respostas das APIs são simuladas.

## Avisos importantes

- Essa ferramenta usa APIs públicas e gratuitas, sem necessidade de chave.
- O ip-api.com gratuito só funciona via HTTP e tem limite de 45 consultas por minuto.
- A geolocalização de IP é aproximada (cidade/região do provedor), não a localização exata de uma pessoa.
- Não use para atividades ilegais ou invasão de privacidade.
- Aprenda, teste e use com responsabilidade.

---

Feito por Leonardo, 17 anos, estudando cibersegurança e programação.
