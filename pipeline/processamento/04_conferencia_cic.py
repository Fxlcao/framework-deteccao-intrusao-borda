"""Compara os 36 atributos do piloto PCAP com a referência do CIC."""
import argparse
import csv
import json
import math
from collections import Counter
from operator import itemgetter
from pathlib import Path
from runpy import run_path

ler = run_path(str(Path(__file__).with_name("01_leitura_pcap.py")))["ler_amostra"]
FLAGS = dict(zip(("FIN", "SYN", "RST", "PSH", "ACK", "ECE", "CWR"),
                 ("fin", "syn", "rst", "psh", "ack", "ece", "cwr")))
CAMPOS_FLAGS = tuple((flag, nome + "_flag_number") for flag, nome in FLAGS.items())
SERVICOS_TCP = {"HTTP":80,"HTTPS":443,"Telnet":23,"SMTP":25,"SSH":22,"IRC":21}


def atributos_pacote(pacote, anterior):
    info = pacote["interpretacao"]
    segundos, nanos = divmod(pacote["timestamp_ns"], 10**9)
    ts = segundos + nanos / 1e9
    tcp = "tcp_flags" in info
    udp = "udp_bytes_total" in info
    portas = {info.get("porta_origem"), info.get("porta_destino")}
    protocolo = info.get("ipv4_protocolo", 0)
    linha = {
        "Header_Length": info.get("tcp_bytes_cabecalho", 8 if udp else 0),
        "Protocol Type": protocolo, "Time_To_Live": info.get("ipv4_ttl", 0),
        "TCP": int(tcp), "UDP": int(udp), "IPv": int(pacote["campo_tipo_ethernet"] == "0x0800"),
        "ICMP": int(protocolo == 1), "IGMP": int(protocolo == 2),
        "DNS": int(udp and 53 in portas), "DHCP": int(udp and portas == {67, 68}),
        "Tot size": pacote["bytes_capturados"], "IAT": 0 if anterior is None else ts - anterior,
    }
    for campo, porta in SERVICOS_TCP.items():
        linha[campo] = int(tcp and porta in portas)
    flags = info.get("tcp_flags", ())
    for flag, campo in CAMPOS_FLAGS:
        linha[campo] = int(flag in flags)

    return ts, linha


def linhas(pcap):
    anterior = None
    for pacote in ler(pcap, 100, True):
        if pacote["campo_tipo_ethernet"] in ("0x0800", "0x0806"):
            anterior, dados = atributos_pacote(pacote, anterior)
            yield pacote["registro"], anterior, dados


def resumir(bloco):
    registros, tempos, dados = zip(*bloco)
    numero = len(dados)
    contagem = Counter(d["Protocol Type"] for d in dados)
    # Assim como o CIC, um empate na moda escolhe o menor código.
    protocolo = max(contagem, key=lambda k: (contagem[k], -k))
    tamanhos = [d["Tot size"] for d in dados]
    total = sum(tamanhos)
    duracao = max(tempos) - min(tempos)

    # Os comprimentos são inteiros. O numerador exato evita cancelamento
    # numérico e fornece a variância amostral usada também no desvio padrão.
    variancia = None
    if numero > 1:
        soma_quadrados = sum(t * t for t in tamanhos)
        variancia = (numero * soma_quadrados - total * total) / (numero * (numero - 1))

    somas = {}
    atributos = {}
    campos = tuple(dados[0])
    # itemgetter lê na ordem da primeira linha mesmo se as demais tiverem outra ordem.
    colunas = zip(*map(itemgetter(*campos), dados))
    for campo, valores in zip(campos, colunas):
        if campo == "Protocol Type":
            atributos[campo] = protocolo
        elif campo == "Tot size":
            atributos[campo] = total / numero
        elif campo == "IAT":
            atributos[campo] = math.fsum(valores) / numero
        else:
            soma = sum(valores)
            somas[campo] = soma
            atributos[campo] = soma / numero

    atributos.update({
        "Number": numero, "Rate": numero / duracao if duracao else None,
        "Tot sum": total, "Min": min(tamanhos), "Max": max(tamanhos),
        "Std": math.sqrt(variancia) if variancia is not None else None,
        "Variance": variancia,
    })
    for flag in ("ack", "syn", "fin", "rst"):
        atributos[flag + "_count"] = somas[flag + "_flag_number"]
    return registros, atributos


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--cenario', choices=('benigno', 'ddos_syn'), default='benigno')
    args = cli.parse_args()
    raiz = Path(__file__).resolve().parents[1]
    pasta = raiz / "work" / "cic"
    pacotes = list(linhas(pasta / f"piloto_{args.cenario}.pcap"))
    with (pasta / f"referencia_{args.cenario}.csv").open(encoding="utf-8-sig", newline="") as arquivo:
        referencia = list(csv.DictReader(arquivo))
    blocos = [pacotes[i:i+10] for i in range(0,len(pacotes),10)]
    janelas = []
    for numero, (bloco, esperado) in enumerate(zip(blocos, referencia, strict=True), 1):
        registros, calculado = resumir(bloco)
        campos = {}
        for chave, valor in sorted(calculado.items()):
            cic = float(esperado[chave])
            diferenca = None if valor is None else valor - cic
            campos[chave] = {"cic": cic, "framework": valor, "diferenca": diferenca,
                            "equivalente": valor is not None and math.isclose(valor,cic,rel_tol=1e-8,abs_tol=1e-9)}
        janelas.append({"janela": numero, "registros": registros, "campos": campos})
    total = sum(len(j["campos"]) for j in janelas)
    iguais = sum(v["equivalente"] for j in janelas for v in j["campos"].values())
    saida = {"total":total,"equivalentes":iguais,"janelas":janelas}
    (raiz / "pipeline" / ("comparacao_piloto.json" if args.cenario == "benigno" else "comparacao_ddos_syn.json")).write_text(json.dumps(saida, indent=2), encoding="utf-8")
    print(f"{len(janelas)} janelas, {iguais}/{total} valores equivalentes")
    for j in janelas:
        for nome, v in j["campos"].items():
            if not v["equivalente"]:
                print(j["janela"], nome, v)


if __name__ == "__main__":
    main()
