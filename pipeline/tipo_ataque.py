"""Tipagem conservadora de alertas por evidência no contexto da janela."""

from collections import Counter, OrderedDict, deque

REGRA_UDP = "udp_flood_por_destino_v1"
REGRA_SCAN = "port_scan_syn_por_par_v1"
UDP_MINIMO = 100
UDP_PERIODO_NS = 100_000_000
SCAN_MINIMO = 20
SCAN_PERIODO_NS = 1_000_000_000
MAX_GRUPOS = 128

REGRA_SYN = "syn_flood_duas_janelas_v1"
SYN_MINIMO = 8
INTERVALO_MAX_NS = 8_000_000


def identificar_tipo(atributos, registros):
    """Retorna um padrão compatível e sua evidência, ou tipo indeterminado."""
    if atributos.get("syn_count", 0) < SYN_MINIMO:
        return None, None

    grupos = {}
    for registro in registros:
        syn = registro.get("syn")
        if syn is not None:
            chave = syn["ipv4_destino"], syn["porta_destino"]
            grupos.setdefault(chave, []).append(syn["timestamp_ns"])
    for (ip, porta), tempos in grupos.items():
        if len(tempos) < SYN_MINIMO:
            continue
        intervalo = max(tempos) - min(tempos)
        if intervalo <= INTERVALO_MAX_NS:
            return "syn_flood", {
                "regra": REGRA_SYN, "interpretacao": "padrao_compativel",
                "alvo_observado": {"ipv4": ip, "porta_tcp": porta},
                "pacotes_syn": len(tempos), "pacotes_na_janela": len(registros),
                "intervalo_syn_ms": intervalo / 1e6,
                "minimo_syn": SYN_MINIMO, "intervalo_maximo_ms": INTERVALO_MAX_NS / 1e6,
                "primeiro_syn_ns": min(tempos), "ultimo_syn_ns": max(tempos),
            }
    return None, None


class ClassificadorTipo:
    """Corrobora a assinatura em janelas sucessivas, sem adiar o alerta binário."""

    def __init__(self):
        self.reiniciar()

    def reiniciar(self):
        self.anterior = None
        self.udp = OrderedDict()
        self.scan = OrderedDict()
        self.ultimo_ns = None

    @staticmethod
    def _grupo(tabela, chave, criar):
        grupo = tabela.get(chave)
        if grupo is None:
            grupo = criar()
            tabela[chave] = grupo
            if len(tabela) > MAX_GRUPOS:
                tabela.popitem(last=False)
        else:
            tabela.move_to_end(chave)
        return grupo

    def _observar(self, registros):
        udp_atual, scan_atual = Counter(), {}
        for registro in registros:
            udp, syn = registro.get("udp"), registro.get("syn")
            rede = udp or syn
            if rede is None:
                continue
            ts = rede["timestamp_ns"]
            if self.ultimo_ns is not None and ts < self.ultimo_ns:
                self.reiniciar()
                udp_atual.clear()
                scan_atual.clear()
            self.ultimo_ns = ts
            ip = rede["ipv4_destino"]
            if udp is not None:
                tempos = self._grupo(self.udp, ip, lambda: deque(maxlen=UDP_MINIMO))
                tempos.append(ts)
                udp_atual[ip] += 1
            elif "ipv4_origem" in syn:
                chave = syn["ipv4_origem"], ip
                porta = syn["porta_destino"]
                portas = self._grupo(self.scan, chave, OrderedDict)
                portas[porta] = ts
                portas.move_to_end(porta)
                if len(portas) > SCAN_MINIMO:
                    portas.popitem(last=False)
                scan_atual.setdefault(chave, set()).add(porta)
        return udp_atual, scan_atual

    def classificar(self, contexto, identificador, ataque=True):
        if not contexto["atributos"].get("UDP") and not contexto["atributos"].get("syn_count"):
            self.anterior = None
            return None, None
        udp_atual, scan_atual = self._observar(contexto["registros"])
        if not ataque:
            self.anterior = None
            return None, None
        candidatos = {}
        tipo, evidencia = self._classificar_syn(contexto, identificador)
        if tipo:
            candidatos[tipo] = evidencia
        for ip, quantidade in udp_atual.items():
            tempos = self.udp.get(ip)
            if (quantidade >= 5 and tempos and len(tempos) == UDP_MINIMO
                    and self.ultimo_ns - tempos[0] <= UDP_PERIODO_NS):
                candidatos["udp_flood"] = {
                    "regra": REGRA_UDP, "interpretacao": "padrao_compativel",
                    "alvo_observado": {"ipv4": ip}, "udp_na_janela": quantidade,
                    "udp_no_intervalo": len(tempos), "intervalo_maximo_ms": 100,
                }
        for chave, atuais in scan_atual.items():
            portas = self.scan.get(chave)
            if (len(atuais) >= 3 and portas and len(portas) == SCAN_MINIMO
                    and self.ultimo_ns - next(iter(portas.values())) <= SCAN_PERIODO_NS):
                candidatos["port_scan"] = {
                    "regra": REGRA_SCAN, "interpretacao": "padrao_compativel",
                    "origem_ipv4": chave[0], "alvo_observado": {"ipv4": chave[1]},
                    "portas_distintas": len(portas), "portas_na_janela": len(atuais),
                    "intervalo_maximo_ms": 1000,
                }
        if len(candidatos) == 1:
            return next(iter(candidatos.items()))
        return None, None

    def _classificar_syn(self, contexto, identificador):
        tipo, evidencia = identificar_tipo(contexto["atributos"], contexto["registros"])
        anterior = self.anterior
        self.anterior = (contexto["janela"], identificador, evidencia) if evidencia else None
        if not anterior or evidencia is None:
            return None, None
        numero, id_anterior, previa = anterior
        intervalo = evidencia["primeiro_syn_ns"] - previa["ultimo_syn_ns"]
        if (contexto["janela"] != numero + 1 or not 0 <= intervalo <= INTERVALO_MAX_NS
                or evidencia["alvo_observado"] != previa["alvo_observado"]):
            return None, None
        return tipo, {**evidencia, "janela_anterior_id": id_anterior,
                      "pacotes_syn_na_janela_anterior": previa["pacotes_syn"],
                      "intervalo_entre_janelas_ms": intervalo / 1e6}
