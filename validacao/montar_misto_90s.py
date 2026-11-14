"""Reconstrói offline o PCAP de validação de 90 s e seu mapa de referência."""
import argparse
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from hashlib import file_digest
import json
from pathlib import Path
from runpy import run_path
import struct
import sys
from tempfile import TemporaryDirectory

PROCESSAMENTO = Path(__file__).resolve().parents[1] / "pipeline" / "processamento"
sys.path.insert(0, str(PROCESSAMENTO))
from interpretacao import interpretar

FORMATOS = run_path(str(PROCESSAMENTO / "01_leitura_pcap.py"))["FORMATOS"]
NS = 10**9
BENIGNO = "BenignTraffic.pcap"
EPISODIOS = (
    ("syn_dos", "DoS-SYN_Flood.pcap", 1659447745, 10, "syn_flood", "192.168.137.187", 4070, None),
    ("udp_dos", "DoS-UDP_Flood.pcap", 1660070246, 22, "udp_flood", "192.168.137.235", 554, None),
    ("scan_1", "Recon-PortScan.pcap", 1664211251, 34, "port_scan", "192.168.137.59", None, "192.168.137.178"),
    ("syn_ddos", "DDoS-SYN_Flood.pcap", 1661537935, 46, "syn_flood", "192.168.137.30", 4070, None),
    ("udp_ddos", "DDoS-UDP_Flood.pcap", 1661951982, 58, "udp_flood", "192.168.137.30", None, None),
    ("scan_2", "Recon-PortScan.pcap", 1664211747, 70, "port_scan", "192.168.137.148", None, "192.168.137.178"),
)
SHA256_ESPERADO = "0b032c730b2dc1a8f4894f58ce0aa62ec28c29bde3db0d0ac92ba62e41059bd3"


@dataclass(frozen=True)
class Pacote:
    indice: int
    tempo: int
    quadro: bytes
    original: int


def ler_pcap(caminho):
    with caminho.open("rb") as arquivo:
        cabecalho = arquivo.read(24)
        if len(cabecalho) != 24 or cabecalho[:4] not in FORMATOS:
            raise ValueError(f"{caminho.name}: cabeçalho PCAP clássico inválido.")
        ordem, escala = FORMATOS[cabecalho[:4]]
        major, minor, _, _, snaplen, enlace = struct.unpack(ordem + "HHIIII", cabecalho[4:])
        if (major, minor, enlace & 0xFFFF) != (2, 4, 1):
            raise ValueError(f"{caminho.name}: esperado PCAP Ethernet 2.4.")
        registro = struct.Struct(ordem + "IIII")
        indice = 0
        while dados := arquivo.read(registro.size):
            indice += 1
            if len(dados) != registro.size:
                raise ValueError(f"{caminho.name}: cabeçalho truncado no registro {indice}.")
            segundo, fracao, capturado, original = registro.unpack(dados)
            if capturado > min(snaplen, original) or fracao * escala >= NS:
                raise ValueError(f"{caminho.name}: metadados inválidos no registro {indice}.")
            quadro = arquivo.read(capturado)
            if len(quadro) != capturado:
                raise ValueError(f"{caminho.name}: quadro truncado no registro {indice}.")
            yield Pacote(indice, segundo * NS + fracao * escala, quadro, original)


def intervalo(pacotes, inicio, duracao):
    for pacote in pacotes:
        if pacote.tempo >= inicio + duracao:
            break
        if pacote.tempo >= inicio:
            yield pacote


def corresponde(pacote, subtipo, destino, porta, origem):
    dados = interpretar(pacote.quadro)
    if dados["estado"] != "ok" or len(pacote.quadro) != pacote.original:
        return False
    if dados.get("ipv4_destino") != destino:
        return False
    if porta is not None and dados.get("porta_destino") != porta:
        return False
    if origem is not None and dados.get("ipv4_origem") != origem:
        return False
    return "udp_bytes_total" in dados if subtipo == "udp_flood" else dados.get("tcp_flags") == ["SYN"]


def montar(capturas, pasta_saida):
    faltantes = sorted({BENIGNO, *(e[1] for e in EPISODIOS)} - {p.name for p in capturas.iterdir() if p.is_file()})
    if faltantes:
        raise ValueError("Capturas ausentes: " + ", ".join(faltantes))
    pcap = pasta_saida / "misto_90s.pcap"
    mapa = pasta_saida / "referencia_misto_90s.json"
    if pcap.exists() or mapa.exists():
        raise FileExistsError("Escolha uma pasta de saída sem o PCAP e o mapa de referência.")

    with closing(ler_pcap(capturas / BENIGNO)) as pacotes:
        primeiro = next(pacotes, None)
        if primeiro is None:
            raise ValueError(f"{BENIGNO}: captura vazia.")
        inicio = primeiro.tempo + 120 * NS
        combinado = [(p.tempo, None, p) for p in intervalo(pacotes, inicio, 90 * NS)]
    if not combinado or combinado[-1][0] - combinado[0][0] <= 85 * NS:
        raise ValueError(f"{BENIGNO}: o recorte de fundo está incompleto.")

    episodios = {}
    for episodio, nome, segundo, posicao, subtipo, destino, porta, origem in EPISODIOS:
        base = segundo * NS
        with closing(ler_pcap(capturas / nome)) as pacotes:
            recorte = [p for p in intervalo(pacotes, base, NS) if corresponde(p, subtipo, destino, porta, origem)]
        if len(recorte) < 100:
            raise ValueError(f"{nome}: recorte {episodio} incompleto ({len(recorte)} registros).")
        combinado.extend((inicio + posicao * NS + p.tempo - base, episodio, p) for p in recorte)
        episodios[episodio] = {"arquivo": nome, "segundo_origem": segundo, "duracao_recorte_s": 1,
                               "insercao_s": posicao, "subtipo": subtipo, "pacotes": len(recorte),
                               "ipv4_destino": destino, "porta": porta, "ipv4_origem": origem}

    combinado.sort(key=lambda linha: (linha[0], linha[1] or "", linha[2].indice))
    pasta_saida.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(dir=pasta_saida) as tmp:
        pcap_tmp = Path(tmp) / pcap.name
        mapa_tmp = Path(tmp) / mapa.name
        registros = []
        with pcap_tmp.open("wb") as arquivo:
            arquivo.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 262144, 1))
            for tempo, episodio, pacote in combinado:
                segundo, fracao = divmod(tempo, NS)
                arquivo.write(struct.pack("<IIII", segundo, fracao, len(pacote.quadro), pacote.original))
                arquivo.write(pacote.quadro)
                registros.append({"episodio": episodio, "registro_origem": pacote.indice,
                                  "tempo_origem_ns": pacote.tempo, "tempo_pcap_ns": tempo})
        with pcap_tmp.open("rb") as arquivo:
            sha = file_digest(arquivo, "sha256").hexdigest()
        if sha != SHA256_ESPERADO:
            raise ValueError(f"SHA-256 diferente do ensaio do TCC ({sha}). Confira as partes originais das capturas.")
        meta = {"arquivo": pcap.name, "sha256": sha, "bytes": pcap_tmp.stat().st_size,
                "fundo": {"arquivo": BENIGNO, "inicio_ns": inicio, "duracao_s": 90},
                "duracao_pcap_s": (combinado[-1][0] - combinado[0][0]) / NS,
                "episodios": episodios, "contagens": dict(Counter(e or "benigno" for _, e, _ in combinado)),
                "registros": registros}
        mapa_tmp.write_text(json.dumps(meta, separators=(",", ":")), encoding="utf-8")
        pcap_tmp.rename(pcap)
        try:
            mapa_tmp.rename(mapa)
        except OSError:
            pcap.unlink()
            raise
    print(f"{pcap} — {len(registros)} registros, SHA-256 {sha}")
    print(mapa)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capturas", type=Path, help="Pasta com os seis PCAPs originais.")
    parser.add_argument("saida", type=Path, help="Pasta para o PCAP misto e o mapa de referência.")
    args = parser.parse_args()
    try:
        montar(args.capturas, args.saida)
    except (OSError, ValueError) as erro:
        parser.exit(1, f"{erro}\n")


if __name__ == "__main__":
    main()
