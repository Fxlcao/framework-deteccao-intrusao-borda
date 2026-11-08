"""Métricas operacionais da execução offline."""
import ctypes
import random
import sys
from collections import Counter
from time import perf_counter_ns, process_time_ns

LIMITE_AMOSTRA = 10_000


def pico_memoria_bytes():
    if sys.platform != "win32":
        return None

    class Contadores(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_uint32), ("page_faults", ctypes.c_uint32)] + [
            (nome, ctypes.c_size_t) for nome in (
                "peak_working_set", "working_set", "peak_paged_pool", "paged_pool",
                "peak_nonpaged_pool", "nonpaged_pool", "pagefile", "peak_pagefile",
            )
        ]

    memoria = Contadores()
    memoria.cb = ctypes.sizeof(memoria)
    consulta = ctypes.windll.kernel32.K32GetProcessMemoryInfo
    consulta.argtypes = [ctypes.c_void_p, ctypes.POINTER(Contadores), ctypes.c_uint32]
    consulta.restype = ctypes.c_int
    return memoria.peak_working_set if consulta(ctypes.c_void_p(-1), ctypes.byref(memoria), memoria.cb) else None


class Distribuicao:
    def __init__(self):
        self.n = 0
        self.soma = 0
        self.maximo = 0
        self.amostra = []
        self.sorteio = random.Random(2026)

    def registrar(self, nanos):
        self.n += 1
        self.soma += nanos
        self.maximo = max(self.maximo, nanos)
        if len(self.amostra) < LIMITE_AMOSTRA:
            self.amostra.append(nanos)
        else:
            indice = self.sorteio.randrange(self.n)
            if indice < LIMITE_AMOSTRA:
                self.amostra[indice] = nanos

    def resumo(self):
        ordenados = sorted(self.amostra)
        if not ordenados:
            return {"n": 0, "n_percentis": 0}

        def percentil(p):
            pos = (len(ordenados) - 1) * p
            i = int(pos)
            a, b = ordenados[i], ordenados[min(i + 1, len(ordenados) - 1)]
            return (a + (b - a) * (pos - i)) / 1e6

        return {"n": self.n, "n_percentis": len(ordenados),
                "media_ms": self.soma / self.n / 1e6, "p50_ms": percentil(0.50),
                "p95_ms": percentil(0.95), "p99_ms": percentil(0.99),
                "max_ms": self.maximo / 1e6}


class Metricas:
    def __init__(self):
        self.inicio_ns = perf_counter_ns()
        self.cpu_inicio_ns = process_time_ns()
        self.eventos = Counter()
        self.pacotes = Counter()
        self.estados = Counter()
        self.alertas = 0
        self.preprocessamento_ns = 0
        self.etapas = {nome: Distribuicao() for nome in (
            "preprocessamento", "inferencia", "validacao_classificacao", "decisao",
            "janela_processamento_ate_decisao",
        )}
        self.janelas_ate_1ms = 0
        self.enfileiramento = Distribuicao()

    def ler(self, eventos):
        while True:
            inicio = perf_counter_ns()
            try:
                evento = next(eventos)
            except StopIteration:
                self.preprocessamento_ns += perf_counter_ns() - inicio
                return
            duracao = perf_counter_ns() - inicio
            self.preprocessamento_ns += duracao
            yield evento, duracao

    def registrar_evento(self, evento):
        tipo = evento["evento"]
        self.eventos[tipo] += 1
        if tipo == "resumo_arquivo":
            self.pacotes.update({k: evento[k] for k in ("lidos", "aceitos", "rejeitados")})

    def registrar_janela(self, evento, tempos):
        self.estados[evento["classificacao"]["estado"]] += 1
        self.alertas += evento["decisao"]["alerta"] is not None
        total = sum(n for n in tempos.values() if n is not None)
        tempos["janela_processamento_ate_decisao"] = total
        evento["tempos_ms"] = {nome: None if n is None else n / 1e6 for nome, n in tempos.items()}
        if evento["classificacao"]["estado"] != "classificada":
            return
        self.janelas_ate_1ms += total <= 1_000_000
        for nome, nanos in tempos.items():
            if nanos is not None:
                self.etapas[nome].registrar(nanos)

    def relatorio(self, execucao_id, tempo_carga_modelo_ns, duracao_operacional_ns, concluida):
        duracao = duracao_operacional_ns / 1e9
        cpu = (process_time_ns() - self.cpu_inicio_ns) / 1e9
        total = (perf_counter_ns() - self.inicio_ns) / 1e9
        pico = pico_memoria_bytes()
        return {
            "execucao_id": execucao_id, "concluida_sem_falhas": concluida,
            "modo": "pcap_offline", "carga_modelo_ms": tempo_carga_modelo_ns / 1e6,
            "duracao_operacional_s": duracao, "duracao_com_inicializacao_s": total,
            "cpu_processo_s": cpu, "cpu_medio_pct_um_nucleo": 100 * cpu / total,
            "memoria_pico_processo_mib": None if pico is None else pico / 2**20,
            "preprocessamento_total_ms": self.preprocessamento_ns / 1e6,
            "eventos": dict(self.eventos), "pacotes": dict(self.pacotes),
            "classificacoes_por_estado": dict(self.estados), "alertas": self.alertas,
            "vazao_pacotes_lidos_s": self.pacotes["lidos"] / duracao,
            "vazao_janelas_classificadas_s": self.estados["classificada"] / duracao,
            "janelas_classificadas_ate_1ms": self.janelas_ate_1ms,
            "etapas": {nome: dist.resumo() for nome, dist in self.etapas.items()},
        }
