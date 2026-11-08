"""Aplica e verifica limites de CPU e memória do processo no Windows."""
import ctypes as c
import os
import sys
from ctypes import wintypes as w

MIB = 2**20
JOB_LIMIT_AFFINITY = 0x10
JOB_LIMIT_PROCESS_MEMORY = 0x100
JOB_EXTENDED_LIMIT_INFORMATION = 9


class LimitesBasicos(c.Structure):
    _fields_ = [
        ("tempo_processo", c.c_int64), ("tempo_job", c.c_int64), ("flags", w.DWORD),
        ("working_set_min", c.c_size_t), ("working_set_max", c.c_size_t),
        ("limite_processos", w.DWORD), ("afinidade", c.c_size_t),
        ("prioridade", w.DWORD), ("escalonamento", w.DWORD),
    ]


class LimitesEstendidos(c.Structure):
    _fields_ = [
        ("basicos", LimitesBasicos), ("contadores_io", c.c_uint64 * 6),
        ("limite_memoria_processo", c.c_size_t), ("limite_memoria_job", c.c_size_t),
        ("pico_memoria_processo", c.c_size_t), ("pico_memoria_job", c.c_size_t),
    ]


class PerfilBorda:
    def __init__(self, cpus, memoria_mib):
        if sys.platform != "win32":
            raise ValueError("Este perfil aplica limites do Windows.")
        if cpus < 1 or not 1 <= memoria_mib <= c.c_size_t(-1).value // MIB:
            raise ValueError("Informe uma quantidade positiva de CPUs e um limite de memória válido.")
        k = self.kernel = c.WinDLL("kernel32", use_last_error=True)
        k.GetCurrentProcess.restype = w.HANDLE
        k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        k.CreateJobObjectW.restype = w.HANDLE
        k.CloseHandle.argtypes = [w.HANDLE]
        k.GetProcessAffinityMask.argtypes = [w.HANDLE, c.POINTER(c.c_size_t), c.POINTER(c.c_size_t)]
        k.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]

        self.processo = k.GetCurrentProcess()
        disponiveis = self._afinidade()
        indices = [i for i in range(disponiveis.bit_length()) if disponiveis & (1 << i)]
        if cpus > len(indices):
            raise ValueError(f"Há apenas {len(indices)} CPUs lógicas disponíveis para o processo.")
        self.indices = indices[:cpus]
        mascara = sum(1 << i for i in self.indices)
        memoria_bytes = memoria_mib * MIB
        self.job = k.CreateJobObjectW(None, None)
        if not self.job:
            raise c.WinError(c.get_last_error())

        limites = LimitesEstendidos()
        limites.basicos.flags = JOB_LIMIT_AFFINITY | JOB_LIMIT_PROCESS_MEMORY
        limites.basicos.afinidade = mascara
        limites.limite_memoria_processo = memoria_bytes
        try:
            self._verificar(k.SetInformationJobObject(
                self.job, JOB_EXTENDED_LIMIT_INFORMATION, c.byref(limites), c.sizeof(limites)))
            self._verificar(k.AssignProcessToJobObject(self.job, self.processo))
            verificado = self._limites()
            if (self._afinidade() != mascara
                    or verificado.limite_memoria_processo != memoria_bytes
                    or not verificado.basicos.flags & JOB_LIMIT_PROCESS_MEMORY):
                raise RuntimeError("O Windows não confirmou os limites solicitados.")
        except BaseException:
            k.CloseHandle(self.job)
            raise

        # As bibliotecas numéricas leem estas opções antes de inicializar.
        for nome in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
            os.environ[nome] = str(cpus)
        self.memoria_mib = memoria_mib

    @staticmethod
    def _verificar(resultado):
        if not resultado:
            raise c.WinError(c.get_last_error())

    def _afinidade(self):
        processo, sistema = c.c_size_t(), c.c_size_t()
        self._verificar(self.kernel.GetProcessAffinityMask(
            self.processo, c.byref(processo), c.byref(sistema)))
        return processo.value

    def _limites(self):
        limites = LimitesEstendidos()
        self._verificar(self.kernel.QueryInformationJobObject(
            self.job, JOB_EXTENDED_LIMIT_INFORMATION, c.byref(limites), c.sizeof(limites), None))
        return limites

    def resumo(self):
        return {
            "cpus_logicas": len(self.indices), "indices_cpus_logicas": self.indices,
            "limite_memoria_comprometida_mib": self.memoria_mib,
            "mecanismo": "Windows Job Object",
        }

    def pico_memoria_mib(self):
        return self._limites().pico_memoria_processo / MIB

    def close(self):
        self.kernel.CloseHandle(self.job)
