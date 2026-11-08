"""Persiste eventos, contexto e resultados locais em SQLite."""
import json
import sqlite3
from pathlib import Path
from uuid import uuid4


class Armazenamento:
    def __init__(self, caminho):
        caminho = Path(caminho).resolve()
        caminho.parent.mkdir(parents=True, exist_ok=True)
        self.conexao = sqlite3.connect(caminho)
        self.conexao.execute("PRAGMA foreign_keys = ON")
        self.conexao.executescript("""
            CREATE TABLE IF NOT EXISTS execucoes (
                id TEXT PRIMARY KEY,
                inicio_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                metadados TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS eventos (
                id TEXT PRIMARY KEY,
                execucao_id TEXT NOT NULL REFERENCES execucoes(id),
                tipo TEXT NOT NULL,
                janela INTEGER,
                contexto TEXT NOT NULL,
                deteccao TEXT,
                classificacao TEXT,
                UNIQUE(execucao_id, janela)
            );
            CREATE TABLE IF NOT EXISTS decisoes (
                evento_id TEXT PRIMARY KEY REFERENCES eventos(id),
                resultado TEXT NOT NULL
            );
        """)

    def iniciar(self, metadados, identificador=None):
        identificador = identificador or uuid4().hex
        with self.conexao:
            self.conexao.execute(
                "INSERT INTO execucoes (id, metadados) VALUES (?, ?)",
                (identificador, json.dumps(metadados, allow_nan=False)),
            )
        return identificador

    def registrar_evento(self, execucao, evento):
        identificador = uuid4().hex
        with self.conexao:
            self.conexao.execute(
                "INSERT INTO eventos (id, execucao_id, tipo, janela, contexto) VALUES (?, ?, ?, ?, ?)",
                (identificador, execucao, evento["evento"], evento.get("janela"),
                 json.dumps(evento, allow_nan=False)),
            )
        return identificador

    def recuperar(self, identificador):
        linha = self.conexao.execute(
            "SELECT contexto FROM eventos WHERE id = ?", (identificador,),
        ).fetchone()
        return json.loads(linha[0]) if linha else None

    def registrar_resultado(self, identificador, deteccao, classificacao, decisao=None):
        with self.conexao:
            alteracao = self.conexao.execute(
                "UPDATE eventos SET deteccao = ?, classificacao = ? WHERE id = ? AND tipo = 'janela'",
                (json.dumps(deteccao, allow_nan=False), json.dumps(classificacao, allow_nan=False),
                 identificador),
            )
            if alteracao.rowcount != 1:
                raise KeyError(f"Janela desconhecida: {identificador}")
            if decisao is not None:
                self.conexao.execute(
                    "INSERT INTO decisoes (evento_id, resultado) VALUES (?, ?)",
                    (identificador, json.dumps(decisao, allow_nan=False)),
                )

    def registrar_lote(self, execucao, lote):
        eventos = []
        atualizacoes = []
        decisoes = []
        for identificador, contexto, deteccao, classificacao, decisao in lote:
            if contexto is None:
                atualizacoes.append((json.dumps(deteccao, allow_nan=False),
                                     json.dumps(classificacao, allow_nan=False),
                                     identificador, execucao))
            else:
                eventos.append((identificador, execucao, contexto["evento"], contexto.get("janela"),
                                json.dumps(contexto, allow_nan=False),
                                None if deteccao is None else json.dumps(deteccao, allow_nan=False),
                                None if classificacao is None else json.dumps(classificacao, allow_nan=False)))
            if decisao is not None:
                decisoes.append((identificador, json.dumps(decisao, allow_nan=False)))
        with self.conexao:
            self.conexao.executemany(
                """INSERT INTO eventos(id, execucao_id, tipo, janela, contexto, deteccao, classificacao)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""", eventos,
            )
            alterados = self.conexao.executemany(
                """UPDATE eventos SET deteccao = ?, classificacao = ?
                   WHERE id = ? AND execucao_id = ? AND tipo = 'janela'""", atualizacoes,
            )
            if alterados.rowcount != len(atualizacoes):
                raise KeyError("Uma janela não foi encontrada para gravar seu resultado.")
            self.conexao.executemany(
                "INSERT INTO decisoes (evento_id, resultado) VALUES (?, ?)", decisoes,
            )

    def close(self):
        self.conexao.close()
