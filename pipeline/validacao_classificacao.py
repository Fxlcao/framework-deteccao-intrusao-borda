"""Interpreta a saída binária do Uller e recupera seu contexto por ID."""
import math



def validar_e_classificar(armazenamento, identificador, deteccao, pacotes_por_janela, tipador=None):
    resultado = {
        "janela_id": identificador,
        "estado": "saida_invalida",
        "classe": None,
        "tipo_ataque": None,
        "probabilidade_ataque": None,
        "motivo": None,
    }
    contexto = armazenamento.recuperar(identificador)
    if contexto is None or contexto.get("evento") != "janela":
        return dict(resultado, estado="contexto_ausente", motivo="janela_nao_encontrada")

    registros = contexto.get("registros", [])
    atributos = contexto.get("atributos", {})
    resultado["contexto"] = {
        "fontes": list(dict.fromkeys(r["arquivo"] for r in registros)),
        "primeiro_registro": registros[0] if registros else None,
        "ultimo_registro": registros[-1] if registros else None,
        "pacotes": len(registros),
    }
    if (not contexto.get("valida") or len(registros) != pacotes_por_janela
            or atributos.get("Number") != pacotes_por_janela):
        return dict(resultado, estado="entrada_invalida",
                    motivo=contexto.get("motivo") or "quantidade_de_pacotes_incompativel")

    if not isinstance(deteccao, dict) or not {"valida", "ataque", "p_ataque"} <= deteccao.keys():
        return dict(resultado, motivo="campos_da_saida_ausentes")
    classe, probabilidade = deteccao["ataque"], deteccao["p_ataque"]
    if deteccao["valida"] is False and classe is None and probabilidade is None:
        return dict(resultado, estado="entrada_rejeitada", motivo="janela_rejeitada_pelo_detector")
    if (deteccao["valida"] is not True or type(classe) is not int or classe not in (0, 1)
            or type(probabilidade) not in (int, float)
            or not 0 <= probabilidade <= 1 or not math.isfinite(probabilidade)):
        return dict(resultado, motivo="valores_da_saida_incompativeis")

    tipo, evidencia = tipador.classificar(contexto, identificador, ataque=classe == 1) if tipador is not None else (None, None)
    if classe == 1:
        resultado["tipo_ataque"] = tipo
        resultado["evidencia_tipo_ataque"] = evidencia
    return dict(resultado, estado="classificada", classe="ataque" if classe else "benigno",
                probabilidade_ataque=probabilidade)
