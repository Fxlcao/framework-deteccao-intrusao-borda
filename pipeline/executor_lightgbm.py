"""Caminho de uma janela para o LightGBM binário do Uller."""
import csv
import ctypes
import math

import numpy as np
from lightgbm import LGBMClassifier
from lightgbm.basic import _C_API_DTYPE_FLOAT32, _C_API_PREDICT_NORMAL, _LIB, _safe_call


def _numero(valor):
    try:
        return float(valor)
    except (TypeError, ValueError):
        return math.nan


class PreditorNativo:
    """Reutiliza a configuração e os buffers de uma linha no fluxo sequencial."""

    def __init__(self, booster, quantidade_atributos):
        self.booster = booster  # O handle do Booster deve permanecer válido até liberar a configuração.
        self.prever = _LIB.LGBM_BoosterPredictForMatSingleRowFast
        self.liberar = _LIB.LGBM_FastConfigFree
        self.entrada = (ctypes.c_float * quantidade_atributos)()
        self.quantidade_saida = ctypes.c_int64()
        self.saida = ctypes.c_double()
        self.config = ctypes.c_void_p()
        _safe_call(_LIB.LGBM_BoosterPredictForMatSingleRowFastInit(
            booster._handle, ctypes.c_int(_C_API_PREDICT_NORMAL), ctypes.c_int(0),
            ctypes.c_int(booster.best_iteration), ctypes.c_int(_C_API_DTYPE_FLOAT32),
            ctypes.c_int32(quantidade_atributos), b"num_threads=1", ctypes.byref(self.config),
        ))

    def __call__(self, valores):
        if not self.config:
            raise RuntimeError("O preditor nativo já foi fechado.")
        self.entrada[:] = valores
        _safe_call(self.prever(
            self.config, self.entrada, ctypes.byref(self.quantidade_saida), ctypes.byref(self.saida),
        ))
        if self.quantidade_saida.value != 1:
            raise ValueError("O LightGBM nativo deve retornar uma probabilidade por janela.")
        return self.saida.value

    def close(self):
        if self.config:
            _safe_call(self.liberar(self.config))
            self.config = ctypes.c_void_p()


class ExecutorLightGBM:
    """Usa o Booster do modelo carregado e preserva o contrato de entrada e saída."""

    def __init__(self, detector, nativo=False):
        modelo = detector.modelo
        self.features = tuple(detector.features)
        if (type(modelo) is not LGBMClassifier or modelo.objective_ != "binary"
                or list(modelo.classes_) != [0, 1]
                or detector.contrato.get("dtype") != "float32"
                or tuple(modelo.feature_name_) != self.features
                or modelo.booster_.pandas_categorical):
            raise ValueError("Modelo incompatível com o executor simplificado.")
        if "Rate" not in self.features or "Number" in self.features:
            raise ValueError("Contrato de atributos incompatível com o executor simplificado.")
        self.booster = modelo.booster_
        self.pacotes = detector.pacotes
        self.limiar = detector.limiar
        self.indice_taxa = self.features.index("Rate")
        self.layout = None
        self.campos = ()
        self.preditor_nativo = PreditorNativo(self.booster, len(self.features)) if nativo else None

    def close(self):
        if self.preditor_nativo is not None:
            self.preditor_nativo.close()

    def _mapear(self, layout):
        normalizados = {str(k).lstrip("\ufeff").strip().replace(" ", "_"): k for k in layout}
        esperados = (*self.features, "Number")
        faltantes = [k for k in esperados if k not in normalizados]
        if faltantes:
            raise ValueError(f"Faltam campos: {faltantes}")
        self.campos = tuple(normalizados[k] for k in esperados)
        self.layout = layout

    def _preparar(self, janela):
        layout = tuple(janela)
        if layout != self.layout:
            self._mapear(layout)
        valores = [_numero(janela[campo]) for campo in self.campos]
        if (valores[-1] != self.pacotes or math.isinf(valores[self.indice_taxa])
                or any(math.isnan(v) for v in valores)):
            return None
        return valores[:-1]

    def _prever(self, valores):
        if self.preditor_nativo is not None:
            return self.preditor_nativo(valores)
        entrada = np.asarray(valores, dtype=np.float32).reshape(1, -1)
        return float(self.booster.predict(entrada, num_threads=1)[0])

    def probabilidade(self, janela):
        valores = self._preparar(janela)
        return None if valores is None else self._prever(valores)

    def classificar(self, janela):
        p = self.probabilidade(janela)
        if p is None:
            return {"ataque": None, "p_ataque": None, "valida": False}
        return {"ataque": int(p >= self.limiar), "p_ataque": round(p, 6), "valida": True}

    def conferir(self, caminho, referencia=None):
        with caminho.open(encoding="utf-8-sig", newline="") as arquivo:
            exemplos = list(csv.DictReader(arquivo))
        if not exemplos:
            raise ValueError("A amostra de conformidade está vazia.")
        for numero, exemplo in enumerate(exemplos, 1):
            p = self.probabilidade(exemplo)
            if (p is None or not math.isfinite(p)
                    or not abs(p - float(exemplo["p_ataque_esperada"])) < 1e-6
                    or int(p >= 0.5) != int(exemplo["ataque_esperado"])
                    or (referencia is not None and p != referencia(exemplo))):
                raise ValueError(f"Falha na conformidade do executor na linha {numero}.")
        return len(exemplos)
