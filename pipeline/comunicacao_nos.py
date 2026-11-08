"""Compartilha alertas persistidos e recebe notificações de um nó conhecido."""
import argparse
import hmac
import http.client
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from time import perf_counter_ns
from urllib.parse import urlsplit

from decisao_alertas import decidir_alerta_externo

ESQUEMA = "alerta-borda-v1"
MAX_BYTES = 8192
MAX_IDADE_S = 300


def conectar(caminho):
    db = sqlite3.connect(caminho)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS comunicacao_recebida (
            origem TEXT NOT NULL, mensagem_id TEXT NOT NULL, mensagem TEXT NOT NULL,
            decisao_local TEXT NOT NULL, recebido_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (origem, mensagem_id)
        );
        CREATE TABLE IF NOT EXISTS comunicacao_envios (
            id INTEGER PRIMARY KEY, execucao_id TEXT NOT NULL, mensagem_id TEXT NOT NULL,
            destino TEXT NOT NULL, estado TEXT NOT NULL, bytes_payload INTEGER NOT NULL,
            duracao_ms REAL NOT NULL, detalhe TEXT, registrado_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    return db


def empacotar(alerta, origem, destino):
    return {"versao": ESQUEMA, "id": alerta["id"], "origem": origem, "destino": destino,
            "enviado_utc": datetime.now(timezone.utc).isoformat(),
            "alerta_utc": alerta["emitido_em_utc"], "janela_id": alerta["janela_id"],
            "classe": "ataque", "acao": "notificar", "justificativa": "classe_ataque",
            "alvo": None, "probabilidade_ataque": alerta["probabilidade_ataque"]}


def validar_mensagem(m, origem, destino):
    campos = ("id", "origem", "destino", "enviado_utc", "alerta_utc", "janela_id")
    esperados = {*campos, "versao", "classe", "acao", "justificativa", "alvo", "probabilidade_ataque"}
    if not isinstance(m, dict) or set(m) != esperados or any(
        not isinstance(m.get(k), str) or not m[k].strip() or len(m[k]) > 128 for k in campos
    ):
        raise ValueError("campos_invalidos")
    if m["origem"] != origem or m["destino"] != destino or origem == destino:
        raise ValueError("origem_ou_destino_invalido")
    if (m.get("versao"), m.get("classe"), m.get("acao"), m.get("justificativa")) != (
            ESQUEMA, "ataque", "notificar", "classe_ataque"):
        raise ValueError("contrato_incompativel")
    p = m.get("probabilidade_ataque")
    if type(p) not in (int, float) or not 0 <= p <= 1 or m.get("alvo") is not None:
        raise ValueError("conteudo_invalido")
    try:
        enviado = datetime.fromisoformat(m["enviado_utc"])
        alerta = datetime.fromisoformat(m["alerta_utc"])
        if enviado.utcoffset() is None or alerta.utcoffset() is None or alerta > enviado:
            raise ValueError
    except ValueError:
        raise ValueError("data_invalida") from None
    idade = (datetime.now(timezone.utc) - enviado).total_seconds()
    if not -10 <= idade <= MAX_IDADE_S:
        raise ValueError("mensagem_fora_da_janela_de_tempo")


def receptor(caminho, porta, origem, no, token):
    class Receptor(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def responder(self, codigo, dados):
            corpo = json.dumps(dados).encode("utf-8")
            self.send_response(codigo)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def do_POST(self):
            if self.path != "/alertas":
                self.responder(404, {"erro": "rota_desconhecida"})
                return
            autorizacao = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(autorizacao, ("Bearer " + token).encode("utf-8")):
                self.responder(401, {"erro": "origem_nao_autenticada"})
                return
            try:
                tamanho = int(self.headers.get("Content-Length", "0"))
                if not 0 < tamanho <= MAX_BYTES or self.headers.get_content_type() != "application/json":
                    raise ValueError("corpo_invalido")
                mensagem = json.loads(self.rfile.read(tamanho))
                validar_mensagem(mensagem, origem, no)
            except (ValueError, UnicodeError, TimeoutError) as erro:
                self.responder(400, {"erro": str(erro)})
                return
            with closing(conectar(caminho)) as db, db:
                dados = json.dumps(mensagem, sort_keys=True, allow_nan=False)
                anterior = db.execute(
                    "SELECT mensagem FROM comunicacao_recebida WHERE origem=? AND mensagem_id=?",
                    (origem, mensagem["id"]),
                ).fetchone()
                if anterior is None:
                    decisao = decidir_alerta_externo(mensagem)
                    db.execute(
                        """INSERT INTO comunicacao_recebida(origem, mensagem_id, mensagem, decisao_local)
                           VALUES(?,?,?,?)""",
                        (origem, mensagem["id"], dados, json.dumps(decisao)),
                    )
                else:
                    antigo = json.loads(anterior[0])
                    if any(antigo[k] != v for k, v in mensagem.items() if k != "enviado_utc"):
                        self.responder(409, {"erro": "id_em_conflito"})
                        return
            estado = "recebido" if anterior is None else "duplicado"
            self.responder(201 if anterior is None else 200, {"estado": estado, "id": mensagem["id"]})

        def log_message(self, *_):
            pass

    return HTTPServer(("127.0.0.1", porta), Receptor)


def enviar_mensagem(url, token, mensagem):
    alvo = urlsplit(url)
    if (not alvo.hostname or alvo.username or alvo.password or alvo.query or alvo.fragment
            or alvo.path not in ("", "/alertas")
            or not (alvo.scheme == "https" or alvo.scheme == "http" and alvo.hostname in ("localhost", "127.0.0.1"))):
        raise ValueError("Informe um destino HTTPS ou HTTP em loopback, na rota /alertas.")
    conexao = http.client.HTTPSConnection if alvo.scheme == "https" else http.client.HTTPConnection
    dados = json.dumps(mensagem, allow_nan=False).encode("utf-8")
    inicio = perf_counter_ns()
    detalhe = None
    estado = "falha"
    try:
        with closing(conexao(alvo.hostname, alvo.port, timeout=3)) as cliente:
            cliente.request("POST", "/alertas", dados, {"Content-Type": "application/json", "Authorization": "Bearer " + token})
            resposta = cliente.getresponse()
            recebido = json.loads(resposta.read(MAX_BYTES))
            if (resposta.status, recebido.get("estado")) in ((201, "recebido"), (200, "duplicado")) and recebido.get("id") == mensagem["id"]:
                estado = recebido["estado"]
            else:
                detalhe = f"HTTP {resposta.status}"
    except (OSError, http.client.HTTPException, ValueError, AttributeError) as erro:
        detalhe = str(erro)
    return {"estado": estado, "detalhe": detalhe, "bytes_payload": len(dados),
            "duracao_ms": (perf_counter_ns() - inicio) / 1e6}


def despachar(db, execucao, url, token, origem, no):
    if not db.execute("SELECT 1 FROM execucoes WHERE id=?", (execucao,)).fetchone():
        raise ValueError("Execução não encontrada.")
    linhas = db.execute(
        """SELECT d.resultado FROM decisoes d JOIN eventos e ON e.id=d.evento_id
           WHERE e.execucao_id=? ORDER BY e.janela""", (execucao,),
    )
    for (decisao,) in linhas:
        alerta = json.loads(decisao).get("alerta")
        if alerta is None:
            continue
        mensagem = empacotar(alerta, origem, no)
        resultado = enviar_mensagem(url, token, mensagem)
        with db:
            db.execute(
                """INSERT INTO comunicacao_envios(execucao_id, mensagem_id, destino, estado,
                                                  bytes_payload, duracao_ms, detalhe)
                   VALUES(?,?,?,?,?,?,?)""",
                (execucao, mensagem["id"], no, resultado["estado"], resultado["bytes_payload"],
                 resultado["duracao_ms"], resultado["detalhe"]),
            )
        yield {"mensagem_id": mensagem["id"], "destino": no, **resultado}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--banco", type=Path, required=True)
    cli.add_argument("--origem", required=True, help="Identificador do nó emissor.")
    cli.add_argument("--no", required=True, help="Identificador do nó destinatário.")
    comandos = cli.add_subparsers(dest="comando", required=True)
    cmd = comandos.add_parser("receber")
    cmd.add_argument("--porta", type=int, default=8765)
    cmd = comandos.add_parser("enviar")
    cmd.add_argument("execucao_id")
    cmd.add_argument("url")
    args = cli.parse_args()
    token = os.environ.get("FRAMEWORK_TOKEN_NOS", "")
    if len(token) < 16 or not token.isascii() or not token.isprintable():
        cli.error("Defina FRAMEWORK_TOKEN_NOS com pelo menos 16 caracteres ASCII imprimíveis.")
    if args.no == args.origem or any(not n.strip() or len(n) > 128 for n in (args.no, args.origem)):
        cli.error("Os identificadores dos nós precisam ser distintos e ter entre 1 e 128 caracteres.")
    try:
        if args.comando == "receber":
            with receptor(args.banco, args.porta, args.origem, args.no, token) as servidor:
                print(f"Escutando em 127.0.0.1:{servidor.server_port}", flush=True)
                servidor.serve_forever()
        else:
            if not args.banco.is_file():
                raise ValueError("Banco de origem não encontrado.")
            falhou = False
            with closing(conectar(args.banco)) as db:
                for resultado in despachar(db, args.execucao_id, args.url, token, args.origem, args.no):
                    print(json.dumps(resultado))
                    falhou |= resultado["estado"] == "falha"
            return int(falhou)
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, sqlite3.Error) as erro:
        cli.exit(1, f"{erro}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
