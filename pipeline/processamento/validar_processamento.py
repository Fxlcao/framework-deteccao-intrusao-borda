"""Validação reproduzível do pré-processamento usando os dois pilotos locais."""
import argparse
import csv
import json
import math
import struct
from pathlib import Path
from tempfile import TemporaryDirectory
from processar_pcap import processar


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("referencias", type=Path)
    args = cli.parse_args()
    evidencias = {}
    for c in ("benigno", "ddos_syn"):
        pcap = args.referencias / f"piloto_{c}.pcap"
        eventos = list(processar([pcap]))
        completas = [e for e in eventos if e["evento"] == "janela"]
        with (args.referencias / f"referencia_{c}.csv").open(newline="", encoding="utf-8-sig") as f:
            ref = list(csv.DictReader(f))
        ref_completas = [r for r in ref if float(r["Number"]) == 10]
        for e, r in zip(completas, ref_completas, strict=True):
            assert e["valida"] and len(e["atributos"]) == 36
            for k, v in e["atributos"].items():
                assert math.isclose(v, float(r[k]), rel_tol=1e-8, abs_tol=1e-9), (c, k, v, r[k])
        evidencias[c] = {"atributos_equivalentes": 36 * len(completas), "eventos": eventos}

    dados = (args.referencias / "piloto_benigno.pcap").read_bytes()
    header = dados[:24]
    ordem = "<" if header[:4].hex() in ("d4c3b2a1", "4d3cb2a1") else ">"
    pacotes = []
    i = 24
    for _ in range(20):
        fim = i + 16 + struct.unpack_from(ordem + "I", dados, i + 8)[0]
        pacotes.append(dados[i:fim])
        i = fim

    with TemporaryDirectory() as tmp:
        def gravar(nome, conteudo):
            destino = Path(tmp) / nome
            destino.write_bytes(conteudo)
            return destino

        inteiro = gravar("inteiro.pcap", header + b"".join(pacotes))
        parte1 = gravar("parte1.pcap", header + b"".join(pacotes[:7]))
        parte2 = gravar("parte2.pcap", header + b"".join(pacotes[7:]))
        base = [e for e in processar([inteiro]) if e["evento"] == "janela"]
        dividida = [e for e in processar([parte1, parte2], True) if e["evento"] == "janela"]
        assert len(base) == len(dividida) == 2
        assert [e["atributos"] for e in base] == [e["atributos"] for e in dividida]
        assert len({r["arquivo"] for r in dividida[0]["registros"]}) == 2
        independentes = list(processar([parte1, parte2]))
        assert sum(e["evento"] == "janela_incompleta" for e in independentes) == 2
        primeira = next(e for e in independentes if e["evento"] == "janela")
        assert primeira["registros"][0]["registro"] == 1
        timestamps = [int.from_bytes(p[:4], "little" if ordem == "<" else "big") +
                      int.from_bytes(p[4:8], "little" if ordem == "<" else "big") / 1e6
                      for p in pacotes[7:17]]
        assert math.isclose(primeira["atributos"]["IAT"], (timestamps[-1]-timestamps[0])/10,
                            abs_tol=1e-9)
        igual = gravar("mesmo_horario.pcap", header + b"".join(pacotes[0][:8] + p[8:] for p in pacotes[:10]))
        janela = next(e for e in processar([igual]) if e["evento"] == "janela")
        assert not janela["valida"] and janela["atributos"]["Rate"] is None
        truncado = gravar("truncado.pcap", header + pacotes[0] + pacotes[1][:-1])
        ruim = gravar("cabecalho_invalido.pcap", b"invalid")
        falhas = list(processar([truncado, ruim, inteiro], True))
        assert [e["proximo_registro"] for e in falhas if e["evento"] == "arquivo_interrompido"] == [2,1]
        assert sum(e["evento"] == "janela" for e in falhas) == 2
        assert any(e["evento"] == "janela_incompleta" and e["motivo"] == "arquivo_interrompido" for e in falhas)
        assert sum(e["evento"] == "pacote_rejeitado" for e in evidencias["benigno"]["eventos"]) == 2
        evidencias["testes"] = {
            "divisao_7_13": {"atributos_identicos": True, "janelas": dividida},
            "capturas_independentes": independentes,
            "rate_indefinido": janela,
            "falhas_de_leitura": falhas,
        }
    print(json.dumps(evidencias, ensure_ascii=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
