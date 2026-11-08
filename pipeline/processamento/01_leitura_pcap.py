"""Leitura e padronização inicial de uma amostra de PCAP Ethernet."""
import argparse
import json
import struct
from datetime import datetime, timezone
from itertools import count
from pathlib import Path

from interpretacao import interpretar

FORMATOS = {
    bytes.fromhex("d4c3b2a1"): ("<", 1000),
    bytes.fromhex("a1b2c3d4"): (">", 1000),
    bytes.fromhex("4d3cb2a1"): ("<", 1),
    bytes.fromhex("a1b23c4d"): (">", 1),
}


def ler_amostra(caminho, limite, interpretar_pacotes=False):
    with caminho.open("rb") as arquivo:
        cabecalho = arquivo.read(24)
        if len(cabecalho) != 24 or cabecalho[:4] not in FORMATOS:
            raise ValueError("Cabeçalho PCAP clássico ausente ou inválido.")
        ordem, fator = FORMATOS[cabecalho[:4]]
        major, minor, _, _, snaplen, enlace = struct.unpack(ordem + "HHIIII", cabecalho[4:])
        if (major, minor) != (2, 4) or enlace & 0xffff != 1:
            raise ValueError("A etapa inicial suporta PCAP 2.4 com quadros Ethernet.")

        ultimo_segundo = None
        texto_segundo = ""
        for numero in (count(1) if limite is None else range(1, limite + 1)):
            posicao = arquivo.tell()
            registro = arquivo.read(16)
            if not registro:
                break
            if len(registro) != 16:
                raise ValueError(f"Cabeçalho incompleto no registro {numero}.")
            segundos, fracao, capturados, originais = struct.unpack(ordem + "IIII", registro)
            nanos = fracao * fator
            if nanos >= 10**9 or capturados > min(snaplen, originais, 16 * 1024**2):
                raise ValueError(f"Metadados inválidos no registro {numero}.")
            quadro = arquivo.read(capturados)
            if len(quadro) != capturados:
                raise ValueError(f"Registro {numero} termina antes do tamanho declarado.")
            if segundos != ultimo_segundo:
                texto_segundo = datetime.fromtimestamp(segundos, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                ultimo_segundo = segundos
            dados = {
                "registro": numero,
                "posicao_bytes": posicao,
                "captura_utc": f"{texto_segundo}.{nanos:09d}Z",
                "timestamp_ns": segundos * 10**9 + nanos,
                "bytes_capturados": capturados,
                "bytes_originais": originais,
                "captura_parcial": capturados < originais,
                "campo_tipo_ethernet": "0x" + quadro[12:14].hex() if capturados >= 14 else None,
            }
            if interpretar_pacotes:
                dados['interpretacao'] = interpretar(quadro)
            yield dados


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--limite", type=int, default=5)
    parser.add_argument('--interpretar', action='store_true', help='Mostra campos dos cabeçalhos dos pacotes.')
    args = parser.parse_args()
    if not 1 <= args.limite <= 1000:
        parser.error("--limite deve estar entre 1 e 1000.")
    origem = args.pcap.resolve()
    try:
        registros = list(ler_amostra(origem, args.limite, args.interpretar))
    except (OSError, ValueError, OverflowError) as erro:
        parser.exit(1, f"Falha em {origem}: {erro}\n")
    print(json.dumps({"origem": str(origem), "registros_lidos": len(registros),
                      "registros": registros}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
