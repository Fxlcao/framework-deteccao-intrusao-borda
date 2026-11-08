"""Enfileira eventos para um único gravador SQLite em segundo plano."""
from contextlib import closing
from queue import Empty, Full, Queue
from threading import Thread
from time import perf_counter_ns
from uuid import uuid4

from armazenamento import Armazenamento

FIM = object()


class ContextoJanela:
    """Disponibiliza ao classificador a janela corrente antes da persistência."""

    def __init__(self, identificador, evento):
        self.identificador = identificador
        self.evento = evento

    def recuperar(self, identificador):
        return self.evento if identificador == self.identificador else None


class GravadorAssincrono:
    def __init__(self, banco, metadados, capacidade=512, tamanho_lote=64):
        if capacidade < 1 or tamanho_lote < 1:
            raise ValueError("Capacidade e tamanho do lote precisam ser positivos.")
        self.banco = banco
        self.metadados = metadados
        self.execucao_id = uuid4().hex
        self.fila = Queue(maxsize=capacidade)
        self.tamanho_lote = tamanho_lote
        self.erro = None
        self.pico_fila_observado = 0
        self.eventos_confirmados = 0
        self.resultados_confirmados = 0
        self.contextos_enfileirados_antes_da_inferencia = 0
        self.contextos_adiados_por_fila_cheia = 0
        self.lotes_confirmados = 0
        self.trabalho_gravador_ns = 0
        self.drenagem_ns = 0
        self.thread = Thread(target=self._gravar, name="gravador-sqlite")

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, tipo, erro, traceback):
        inicio = perf_counter_ns()
        try:
            self._enfileirar(FIM)
        finally:
            self.thread.join()
            self.drenagem_ns = perf_counter_ns() - inicio
        self._verificar_erro()

    def _verificar_erro(self):
        if self.erro is not None:
            raise RuntimeError("Falha no armazenamento assíncrono. A fila pode conter eventos não gravados.") from self.erro

    def _enfileirar(self, item):
        while True:
            self._verificar_erro()
            try:
                self.fila.put(item, timeout=0.1)
            except Full:
                continue
            self._verificar_erro()
            return

    def registrar(self, identificador, contexto, deteccao=None, classificacao=None, decisao=None):
        self._enfileirar((identificador, contexto, deteccao, classificacao, decisao))
        self.pico_fila_observado = max(self.pico_fila_observado, self.fila.qsize())

    def tentar_registrar_contexto(self, identificador, contexto):
        """Entrega o contexto ao gravador sem esperar por espaço na fila."""
        self._verificar_erro()
        try:
            self.fila.put_nowait((identificador, contexto, None, None, None))
        except Full:
            self.contextos_adiados_por_fila_cheia += 1
            return False
        self.contextos_enfileirados_antes_da_inferencia += 1
        self.pico_fila_observado = max(self.pico_fila_observado, self.fila.qsize())
        return True

    def _gravar(self):
        try:
            with closing(Armazenamento(self.banco)) as db:
                db.iniciar(self.metadados, identificador=self.execucao_id)
                encerrando = False
                while not encerrando:
                    item = self.fila.get()
                    if item is FIM:
                        return
                    lote = [item]
                    while len(lote) < self.tamanho_lote:
                        try:
                            item = self.fila.get_nowait()
                        except Empty:
                            break
                        if item is FIM:
                            encerrando = True
                            break
                        lote.append(item)
                    inicio = perf_counter_ns()
                    db.registrar_lote(self.execucao_id, lote)
                    self.trabalho_gravador_ns += perf_counter_ns() - inicio
                    self.eventos_confirmados += sum(item[1] is not None for item in lote)
                    self.resultados_confirmados += sum(item[3] is not None for item in lote)
                    self.lotes_confirmados += 1
        except Exception as erro:
            self.erro = erro

    def resumo(self):
        return {"capacidade_fila_eventos": self.fila.maxsize,
                "pico_fila_observado": self.pico_fila_observado,
                "limite_eventos_por_lote": self.tamanho_lote,
                "eventos_confirmados": self.eventos_confirmados,
                "resultados_confirmados": self.resultados_confirmados,
                "contextos_enfileirados_antes_da_inferencia": self.contextos_enfileirados_antes_da_inferencia,
                "contextos_adiados_por_fila_cheia": self.contextos_adiados_por_fila_cheia,
                "lotes_confirmados": self.lotes_confirmados,
                "trabalho_gravador_ms": self.trabalho_gravador_ns / 1e6,
                "drenagem_final_ms": self.drenagem_ns / 1e6}
