"""Executa o pré-processamento de PCAP e a detecção do Uller em uma passagem."""
import argparse
import json
import sys
import math
from contextlib import ExitStack
from hashlib import file_digest
from pathlib import Path
from time import perf_counter_ns

from uuid import uuid4

from gravador_assincrono import ContextoJanela, GravadorAssincrono
from decisao_alertas import POLITICA, decidir
from metricas import Metricas
from perfil_borda import PerfilBorda
from validacao_classificacao import validar_e_classificar
from tipo_ataque import ClassificadorTipo


def main():
    pasta = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", type=Path, nargs="+")
    parser.add_argument("--modelo", type=Path,
                        default=pasta.parent / "algoritimo.Att" / "pacote_modelo")
    parser.add_argument("--processamento", type=Path, default=pasta / "processamento")
    parser.add_argument("--limite", type=int, help="Lê até este número de registros por arquivo.")
    parser.add_argument("--continuo", action="store_true",
                        help="Mantém o estado entre partes consecutivas da mesma captura.")
    parser.add_argument('--banco', type=Path, default=pasta.parent / 'dados' / 'framework.sqlite3',
                        help='Banco SQLite para registrar a execução e seus resultados.')
    parser.add_argument('--metricas', type=Path, help='Grava o resumo das métricas em um novo arquivo JSON.')
    parser.add_argument('--limiar', type=float, help='Limiar de ataque para esta execução, de 0 a 1.')
    parser.add_argument("--perfil-borda", action="store_true",
                        help="Aplica os limites padrão de 2 CPUs lógicas e 1024 MiB de memória.")
    parser.add_argument("--cpu-logicas", type=int, help="CPUs lógicas permitidas no perfil de borda.")
    parser.add_argument("--memoria-mib", type=int, help="Limite de memória comprometida do processo.")
    parser.add_argument("--executor", choices=("nativo", "simplificado", "original"), default="nativo",
                        help="Seleciona o caminho de inferência para comparação ou compatibilidade.")
    args = parser.parse_args()
    if args.limiar is not None and not 0 <= args.limiar <= 1:
        parser.error('--limiar deve estar entre 0 e 1.')
    if args.metricas is not None and (args.metricas.exists() or args.metricas.resolve() == args.banco.resolve()):
        parser.error('--metricas precisa apontar para um arquivo novo, diferente do banco.')
    metricas = Metricas() if args.metricas is not None else None
    if args.limite is not None and args.limite < 1:
        parser.error("--limite deve ser positivo.")
    if args.continuo and args.limite is not None:
        parser.error('--continuo exige a leitura integral de cada parte.')
    modelo = args.modelo.resolve()
    processamento = args.processamento.resolve()
    for caminho in (modelo / "ids_modelo.py", processamento / "processar_pcap.py"):
        if not caminho.is_file():
            parser.error(f"Arquivo necessário ausente: {caminho}")
    perfil = None
    if args.perfil_borda or args.cpu_logicas is not None or args.memoria_mib is not None:
        try:
            perfil = PerfilBorda(
                args.cpu_logicas if args.cpu_logicas is not None else 2,
                args.memoria_mib if args.memoria_mib is not None else 1024,
            )
        except (OSError, ValueError, RuntimeError) as erro:
            parser.exit(1, f"Não foi possível aplicar o perfil de borda: {erro}\n")
    try:
        with ExitStack() as recursos:
            return executar(args, parser, metricas, modelo, processamento, perfil, recursos)
    finally:
        if perfil is not None:
            perfil.close()


def executar(args, parser, metricas, modelo, processamento, perfil, recursos):
    sys.path[:0] = [str(modelo), str(processamento)]
    try:
        import ids_modelo
        from processar_pcap import processar

        inicio_carga = perf_counter_ns()
        detector = ids_modelo.carregar(pasta=modelo, limiar=args.limiar)
        tempo_carga = perf_counter_ns() - inicio_carga
    except (ImportError, OSError, ValueError, AttributeError) as erro:
        parser.exit(1, f"Falha ao carregar o pipeline ou o detector: {erro}\n")

    classificar = ids_modelo.classificar
    modo_executor = "original"
    if args.executor != "original":
        from executor_lightgbm import ExecutorLightGBM
        from lightgbm.basic import LightGBMError

        try:
            adaptador = ExecutorLightGBM(detector)
            adaptador.conferir(modelo / "exemplo_conformidade.csv")
            classificar = adaptador.classificar
            modo_executor = "simplificado"
        except (ValueError, OSError, KeyError, AttributeError, LightGBMError) as erro:
            print(f"Executor original selecionado por compatibilidade: {erro}", file=sys.stderr)
        if args.executor == "nativo" and modo_executor == "simplificado":
            try:
                nativo = ExecutorLightGBM(detector, nativo=True)
                recursos.callback(nativo.close)
                nativo.conferir(modelo / "exemplo_conformidade.csv", referencia=adaptador.probabilidade)
                classificar = nativo.classificar
                modo_executor = "nativo"
            except (ValueError, OSError, KeyError, AttributeError, LightGBMError) as erro:
                print(f"Executor simplificado selecionado por compatibilidade: {erro}", file=sys.stderr)

    artefatos = {}
    for nome in ("contrato.json", "ids_modelo.py", detector.contrato["arquivo_modelo"]):
        with (modelo / nome).open("rb") as arquivo:
            artefatos[nome] = file_digest(arquivo, "sha256").hexdigest()

    falhou = False
    tipador = ClassificadorTipo()
    metadados = {
        "modelo": str(modelo), "artefatos_sha256": artefatos, "limiar": detector.limiar,
        "pcaps": [str(p.resolve()) for p in args.pcaps], "continuo": args.continuo,
        "limite_por_arquivo": args.limite, "politica_decisao": POLITICA,
        "persistencia": "sqlite_assincrona_contexto_em_paralelo",
        "executor": modo_executor,
        "perfil_recursos": perfil.resumo() if perfil is not None else None,
    }
    banco_inicial_bytes = args.banco.stat().st_size if metricas is not None and args.banco.is_file() else 0
    inicio_operacional = perf_counter_ns()
    with GravadorAssincrono(args.banco, metadados) as armazenamento:
        execucao = armazenamento.execucao_id
        acumulado_pre = 0
        eventos = processar(args.pcaps, args.continuo, args.limite)
        fluxo = metricas.ler(eventos) if metricas is not None else ((e, 0) for e in eventos)
        for evento, tempo_pre in fluxo:
            acumulado_pre += tempo_pre
            if metricas is not None:
                metricas.registrar_evento(evento)
            identificador = uuid4().hex
            contexto = dict(evento)
            deteccao = classificacao = decisao = None
            contexto_enfileirado = False
            tempo_fila_contexto = 0
            evento["execucao_id"] = execucao
            evento["evento_id"] = identificador
            if evento["evento"] == "janela":
                if evento["valida"]:
                    inicio_fila = perf_counter_ns()
                    contexto_enfileirado = armazenamento.tentar_registrar_contexto(identificador, contexto)
                    tempo_fila_contexto = perf_counter_ns() - inicio_fila
                inicio = perf_counter_ns()
                deteccao = (
                    classificar(evento["atributos"])
                    if evento["valida"]
                    else {"ataque": None, "p_ataque": None, "valida": False}
                )
                tempo_inferencia = perf_counter_ns() - inicio if evento["valida"] else None
                inicio = perf_counter_ns()
                classificacao = validar_e_classificar(
                    ContextoJanela(identificador, contexto), identificador, deteccao, detector.pacotes, tipador,
                )
                tempo_validacao = perf_counter_ns() - inicio
                # JSON não representa infinitos ou NaN. Preserve o valor textual para diagnóstico.
                if isinstance(deteccao, dict):
                    deteccao = {
                        k: str(v) if type(v) is float and not math.isfinite(v) else v
                        for k, v in deteccao.items()
                    }
                inicio = perf_counter_ns()
                decisao = decidir(classificacao, execucao)
                tempo_decisao = perf_counter_ns() - inicio
                evento["decisao"] = decisao
                evento["deteccao"] = deteccao
                evento["classificacao"] = classificacao
                falhou |= classificacao["estado"] in ("saida_invalida", "contexto_ausente")
                if metricas is not None:
                    metricas.registrar_janela(evento, {
                        "preprocessamento": acumulado_pre, "inferencia": tempo_inferencia,
                        "validacao_classificacao": tempo_validacao, "decisao": tempo_decisao,
                    })
                acumulado_pre = 0
            elif evento["evento"] in ("janela_incompleta", "arquivo_interrompido"):
                acumulado_pre = 0
                tipador.reiniciar()
            elif evento["evento"] == "resumo_arquivo" and not args.continuo:
                acumulado_pre = 0
                tipador.reiniciar()
            inicio_fila = perf_counter_ns()
            armazenamento.registrar(identificador, None if contexto_enfileirado else contexto,
                                     deteccao, classificacao, decisao)
            if metricas is not None:
                tempo_fila = tempo_fila_contexto + perf_counter_ns() - inicio_fila
                metricas.enfileiramento.registrar(tempo_fila)
                evento["enfileiramento_ms"] = tempo_fila / 1e6
            print(json.dumps(evento, allow_nan=False))
            falhou |= evento["evento"] == "arquivo_interrompido"
        if metricas is not None:
            sys.stdout.flush()
            duracao_producao = perf_counter_ns() - inicio_operacional
    if metricas is not None:
        duracao_operacional = perf_counter_ns() - inicio_operacional
        relatorio = metricas.relatorio(execucao, tempo_carga, duracao_operacional, not falhou)
        relatorio["duracao_ate_fim_da_producao_s"] = duracao_producao / 1e9
        relatorio["persistencia_assincrona"] = {
            **armazenamento.resumo(), "enfileiramento": metricas.enfileiramento.resumo(),
        }
        relatorio["perfil_recursos"] = perfil.resumo() if perfil is not None else None
        if perfil is not None:
            relatorio["memoria_pico_comprometida_mib"] = perfil.pico_memoria_mib()
        banco_final_bytes = args.banco.stat().st_size
        relatorio["sqlite_arquivo_principal_bytes"] = banco_final_bytes
        relatorio["sqlite_crescimento_arquivo_principal_bytes"] = banco_final_bytes - banco_inicial_bytes
        relatorio["configuracao"] = {
            "pcaps": [str(p.resolve()) for p in args.pcaps],
            "limite_por_arquivo": args.limite, "continuo": args.continuo,
            "banco": str(args.banco.resolve()), "limiar": detector.limiar,
            "politica_decisao": POLITICA, "artefatos_sha256": artefatos, "executor": modo_executor,
        }
        with args.metricas.open("x", encoding="utf-8") as destino:
            json.dump(relatorio, destino, ensure_ascii=False, allow_nan=False, indent=2)
            destino.write("\n")
    return int(falhou)


if __name__ == "__main__":
    raise SystemExit(main())
