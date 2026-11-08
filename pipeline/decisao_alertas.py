"""Aplica a política local de alertas à classificação padronizada."""
from datetime import datetime, timezone

POLITICA = "alerta_local_binario_v1"


def decidir(classificacao, execucao_id):
    janela_id = classificacao["janela_id"]
    decisao = {"janela_id": janela_id, "politica": POLITICA, "alerta": None}
    if classificacao["estado"] != "classificada":
        return dict(decisao, acao="registrar_sem_alerta",
                    motivo=classificacao["motivo"] or classificacao["estado"])
    if classificacao["classe"] == "benigno":
        return dict(decisao, acao="registrar_sem_alerta", motivo="classe_benigno")
    if classificacao["classe"] != "ataque":
        return dict(decisao, acao="registrar_sem_alerta", motivo="classe_desconhecida")

    alerta = {
        "id": f"alerta-{janela_id}",
        "execucao_id": execucao_id,
        "janela_id": janela_id,
        "emitido_em_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "prioridade": "normal",
        "classe": "ataque",
        "probabilidade_ataque": classificacao["probabilidade_ataque"],
        "tipo_ataque": classificacao["tipo_ataque"],
        "evidencia_tipo_ataque": classificacao.get("evidencia_tipo_ataque"),
        "contexto": classificacao["contexto"],
    }
    return dict(decisao, acao="emitir_alerta", motivo="classe_ataque", alerta=alerta)


def decidir_alerta_externo(mensagem):
    """Encaminha a notificação de outro nó para análise local."""
    return {"acao": "registrar_para_analise", "motivo": "alerta_de_no_vizinho",
            "origem": mensagem["origem"], "mensagem_id": mensagem["id"]}
