"""Retroalimentação supervisionada sobre janelas persistidas pelo framework."""
import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path


def conectar(caminho):
    db = sqlite3.connect(caminho.resolve().as_uri() + "?mode=rw", uri=True)
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("""
        CREATE TABLE IF NOT EXISTS revisoes (
            id INTEGER PRIMARY KEY,
            evento_id TEXT NOT NULL REFERENCES eventos(id),
            classe TEXT NOT NULL CHECK(classe IN ('benigno','ataque')),
            responsavel TEXT NOT NULL,
            referencia TEXT NOT NULL,
            registrado_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    db.execute("CREATE INDEX IF NOT EXISTS revisoes_evento ON revisoes(evento_id, id)")
    return db


def rotular(db, evento_id, classe, responsavel, referencia):
    if not responsavel.strip() or not referencia.strip():
        raise ValueError("Informe o responsável e a evidência usada na revisão.")
    with db:
        linha = db.execute(
            "SELECT contexto FROM eventos WHERE id=? AND tipo='janela'", (evento_id,),
        ).fetchone()
        if not linha or not json.loads(linha[0]).get("valida"):
            raise ValueError("O identificador precisa apontar para uma janela local válida.")
        return db.execute(
            "INSERT INTO revisoes(evento_id, classe, responsavel, referencia) VALUES(?,?,?,?)",
            (evento_id, classe, responsavel, referencia),
        ).lastrowid


def revisadas(db, execucao):
    consulta = """
        SELECT e.id, e.contexto, e.classificacao, r.classe, r.responsavel,
               r.referencia, r.registrado_utc, x.metadados
        FROM eventos e JOIN execucoes x ON x.id=e.execucao_id
        JOIN revisoes r ON r.id=(SELECT MAX(id) FROM revisoes WHERE evento_id=e.id)
        WHERE e.execucao_id=? ORDER BY e.janela
    """
    for id_, contexto, resultado, classe, autor, ref, data, meta in db.execute(consulta, (execucao,)):
        janela = json.loads(contexto)
        yield {
            "janela_id": id_, "execucao_id": execucao,
            "atributos": janela["atributos"], "registros": janela["registros"],
            "classificacao": json.loads(resultado) if resultado else None,
            "referencia": {"classe": classe, "responsavel": autor, "evidencia": ref, "registrado_utc": data},
            "artefatos_sha256": json.loads(meta).get("artefatos_sha256", {}),
        }


def avaliar(janelas, limiares):
    contagens = {l: dict(tp=0, tn=0, fp=0, fn=0) for l in limiares}
    for janela in janelas:
        resultado = janela["classificacao"]
        if resultado is None or resultado["estado"] != "classificada":
            continue
        esperado = janela["referencia"]["classe"] == "ataque"
        for limiar, c in contagens.items():
            previsto = resultado["probabilidade_ataque"] >= limiar
            c[("tp" if previsto else "fn") if esperado else ("fp" if previsto else "tn")] += 1
    if not any(sum(c.values()) for c in contagens.values()):
        raise ValueError("A execução não tem janelas revisadas com probabilidade válida.")
    return [{"limiar": l, **c} for l, c in contagens.items()]


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--banco", type=Path,
                     default=Path(__file__).resolve().parents[1] / "dados" / "framework.sqlite3")
    comandos = cli.add_subparsers(dest="comando", required=True)
    cmd = comandos.add_parser("rotular")
    cmd.add_argument("janela_id")
    cmd.add_argument("classe", choices=("benigno", "ataque"))
    cmd.add_argument("--responsavel", required=True)
    cmd.add_argument("--referencia", required=True)
    cmd = comandos.add_parser("exportar")
    cmd.add_argument("execucao_id")
    cmd.add_argument("saida", type=Path)
    cmd = comandos.add_parser("avaliar")
    cmd.add_argument("execucao_id")
    cmd.add_argument("--limiares", nargs="+", type=float, required=True)
    args = cli.parse_args()
    try:
        with closing(conectar(args.banco)) as db:
            if args.comando == "rotular":
                print(f"Revisão registrada: {rotular(db, args.janela_id, args.classe, args.responsavel, args.referencia)}")
            elif args.comando == "exportar":
                with args.saida.open("x", encoding="utf-8") as f:
                    for janela in revisadas(db, args.execucao_id):
                        f.write(json.dumps(janela, ensure_ascii=False, allow_nan=False) + "\n")
            else:
                if not all(0 <= l <= 1 for l in args.limiares):
                    raise ValueError("Os limiares devem estar entre 0 e 1.")
                print(json.dumps(avaliar(revisadas(db, args.execucao_id), args.limiares), indent=2))
    except (ValueError, OSError, sqlite3.Error) as erro:
        cli.exit(1, f"{erro}\n")


if __name__ == "__main__":
    main()
