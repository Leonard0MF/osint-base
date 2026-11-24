"""Testes offline (APIs simuladas). Rode com: python -m unittest -v"""

import unittest
from unittest import mock

import osint


def resposta(status=200, dados=None, headers=None):
    r = mock.Mock()
    r.status_code = status
    r.json.return_value = dados or {}
    r.headers = headers or {}
    return r


class TestValidacao(unittest.TestCase):
    def test_ip_invalido(self):
        with self.assertRaises(osint.ConsultaErro):
            osint.consulta_ip("999.1.1.1")

    def test_ip_privado(self):
        for ip in ("192.168.0.1", "127.0.0.1", "10.0.0.5"):
            with self.assertRaises(osint.ConsultaErro):
                osint.consulta_ip(ip)

    def test_limpa_dominio(self):
        self.assertEqual(osint.limpa_dominio("https://WWW.Example.com/a?b#c"), "www.example.com")
        self.assertEqual(osint.limpa_dominio("example.com:8080"), "example.com")

    def test_dominio_invalido(self):
        with self.assertRaises(osint.ConsultaErro):
            osint.consulta_whois("nao_e_dominio")

    def test_github_username_invalido(self):
        with self.assertRaises(osint.ConsultaErro):
            osint.busca_github_username("nome com espaço")


class TestConsultas(unittest.TestCase):
    @mock.patch("osint.requests.get")
    def test_ip_sucesso(self, get):
        get.return_value = resposta(dados={"status": "success", "query": "8.8.8.8",
                                           "country": "EUA", "isp": "Google", "lat": 1, "lon": 2})
        d = osint.consulta_ip("8.8.8.8")
        self.assertEqual(d["ISP"], "Google")
        self.assertEqual(d["Coordenadas"], "1, 2")
        self.assertEqual(get.call_args.kwargs["timeout"], osint.TIMEOUT)

    @mock.patch("osint.requests.get")
    def test_ip_falha_api(self, get):
        get.return_value = resposta(dados={"status": "fail", "message": "reserved range"})
        with self.assertRaises(osint.ConsultaErro):
            osint.consulta_ip("8.8.8.8")

    @mock.patch("osint.requests.get", side_effect=osint.requests.exceptions.Timeout)
    def test_timeout(self, _):
        with self.assertRaisesRegex(osint.ConsultaErro, "timeout"):
            osint.consulta_ip("8.8.8.8")

    @mock.patch("osint.requests.get")
    def test_github_404(self, get):
        get.return_value = resposta(404)
        with self.assertRaisesRegex(osint.ConsultaErro, "não encontrado"):
            osint.busca_github_username("alguem")

    @mock.patch("osint.requests.get")
    def test_github_rate_limit_nao_e_404(self, get):
        get.return_value = resposta(403, headers={"X-RateLimit-Reset": "1700000000"})
        with self.assertRaisesRegex(osint.ConsultaErro, "Limite"):
            osint.busca_github_username("alguem")

    @mock.patch("osint.requests.get")
    def test_github_sucesso(self, get):
        get.return_value = resposta(dados={"login": "torvalds", "public_repos": 7,
                                           "created_at": "2011-09-03T15:26:22Z"})
        d = osint.busca_github_username("@torvalds")
        self.assertEqual(d["Usuário"], "torvalds")
        self.assertEqual(d["Conta criada em"], "03/09/2011")

    def test_formata_data_lista(self):
        from datetime import datetime
        self.assertEqual(osint._formata_data([datetime(2020, 1, 2, 3, 4)]), "02/01/2020 03:04")


class TestCLI(unittest.TestCase):
    def test_codigo_saida_erro(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(osint.main(["ip", "abc"]), 1)

    def test_import_nao_pede_input(self):
        # antes, o script chamava input() ao ser importado
        import importlib
        with mock.patch("builtins.input", side_effect=AssertionError("input chamado")):
            importlib.reload(osint)


if __name__ == "__main__":
    unittest.main()
