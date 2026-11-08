"""Produz eventos JSONL de pré-processamento para arquivos PCAP Ethernet."""
import argparse
import json
from pathlib import Path
from runpy import run_path

cic = run_path(str(Path(__file__).with_name("04_conferencia_cic.py")))
ler = cic["ler"]
atributos_pacote = cic["atributos_pacote"]
resumir = cic["resumir"]


def processar(arquivos, continuo=False, limite=None):
    bloco = []
    anterior = None
    numero = 0
    for arquivo in arquivos:
        origem = str(arquivo.resolve())
        lidos = aceitos = rejeitados = 0
        try:
            for pacote in ler(arquivo, limite, True):
                lidos += 1
                ref = {"arquivo": origem, "registro": pacote["registro"],
                       "posicao_bytes": pacote["posicao_bytes"], "captura_utc": pacote["captura_utc"]}
                tipo = pacote["campo_tipo_ethernet"]
                info = pacote["interpretacao"]
                motivo = None
                if tipo is None:
                    motivo = "ethernet_incompleto"
                elif tipo not in ("0x0800", "0x0806"):
                    motivo = "fora_do_recorte_ipv4_arp"
                elif pacote["captura_parcial"] or info.get("ipv4_captura_incompleta"):
                    motivo = "captura_incompleta"
                elif tipo == "0x0806" and pacote["bytes_capturados"] < 42:
                    motivo = "arp_incompleto"
                elif tipo == "0x0800" and info["estado"] not in ("ok", "fragmento_sem_cabecalho_transporte"):
                    motivo = info["estado"]
                if motivo:
                    rejeitados += 1
                    yield dict(ref, evento="pacote_rejeitado", motivo=motivo)
                    continue
                if (info.get("tcp_flags") == ["SYN"] and not info["ipv4_fragmentado"]):
                    ref["syn"] = {
                        "ipv4_origem": info["ipv4_origem"],
                        "ipv4_destino": info["ipv4_destino"],
                        "porta_destino": info["porta_destino"],
                        "timestamp_ns": pacote["timestamp_ns"],
                    }
                elif "udp_bytes_total" in info and not info["ipv4_fragmentado"]:
                    ref["udp"] = {
                        "ipv4_destino": info["ipv4_destino"],
                        "timestamp_ns": pacote["timestamp_ns"],
                    }
                anterior, dados = atributos_pacote(pacote, anterior)
                aceitos += 1
                bloco.append((ref, anterior, dados))
                if len(bloco) == 10:
                    numero += 1
                    registros, atributos = resumir(bloco)
                    yield {"evento": "janela", "janela": numero, "registros": registros,
                           "valida": atributos["Rate"] is not None,
                           "motivo": "duracao_zero" if atributos["Rate"] is None else None,
                           "atributos": atributos}
                    bloco.clear()
        except (ValueError, OSError, OverflowError) as erro:
            yield {"evento": "arquivo_interrompido", "arquivo": origem,
                   "proximo_registro": lidos + 1, "motivo": str(erro)}
            if bloco:
                yield {"evento": "janela_incompleta", "motivo": "arquivo_interrompido",
                       "registros": [item[0] for item in bloco]}
            bloco.clear()
            anterior = None
            yield {"evento": "resumo_arquivo", "arquivo": origem, "lidos": lidos,
                   "aceitos": aceitos, "rejeitados": rejeitados, "interrompido": True}
            continue
        yield {"evento": "resumo_arquivo", "arquivo": origem, "lidos": lidos,
               "aceitos": aceitos, "rejeitados": rejeitados, "interrompido": False}
        if not continuo:
            if bloco:
                yield {"evento": "janela_incompleta", "motivo": "fim_da_captura",
                       "registros": [item[0] for item in bloco]}
            bloco.clear()
            anterior = None
    if bloco:
        yield {"evento": "janela_incompleta", "motivo": "fim_da_sequencia",
               "registros": [item[0] for item in bloco]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", type=Path, nargs="+")
    parser.add_argument("--continuo", action="store_true",
                        help="Preserva o estado entre partes consecutivas informadas na ordem original.")
    args = parser.parse_args()
    falhou = False
    for evento in processar(args.pcaps, args.continuo):
        print(json.dumps(evento, allow_nan=False))
        falhou |= evento["evento"] == "arquivo_interrompido"
    return int(falhou)


if __name__ == "__main__":
    raise SystemExit(main())
