"""Extrai campos observáveis dos cabeçalhos de um quadro Ethernet."""
from ipaddress import IPv4Address
from struct import unpack_from


def interpretar(quadro):
    if len(quadro) < 14:
        return {"estado": "ethernet_incompleto"}

    tipo = unpack_from("!H", quadro, 12)[0]
    inicio = 14
    vlans = []
    while tipo in (0x8100, 0x88a8, 0x9100):
        if len(quadro) < inicio + 4:
            return {"estado": "vlan_incompleta", "vlans": vlans}
        tag, tipo = unpack_from("!HH", quadro, inicio)
        vlans.append(tag & 0xfff)
        inicio += 4

    dados = {"ethertype": f"0x{tipo:04x}", "vlans": vlans}
    if tipo != 0x0800:
        return dict(dados, estado="fora_do_recorte_ipv4")
    ip = quadro[inicio:]
    if len(ip) < 20:
        return dict(dados, estado="ipv4_incompleto")
    cabecalho = (ip[0] & 15) * 4
    total = unpack_from("!H", ip, 2)[0]
    if ip[0] >> 4 != 4 or not 20 <= cabecalho <= total:
        return dict(dados, estado="ipv4_invalido")
    if len(ip) < cabecalho:
        return dict(dados, estado="ipv4_incompleto")

    fragmento = unpack_from("!H", ip, 6)[0]
    protocolo = ip[9]
    dados.update(
        estado="ok", ipv4_origem=str(IPv4Address(ip[12:16])),
        ipv4_destino=str(IPv4Address(ip[16:20])),
        ipv4_ttl=ip[8], ipv4_protocolo=protocolo,
        ipv4_bytes_cabecalho=cabecalho, ipv4_bytes_total=total,
        ipv4_fragmentado=bool(fragmento & 0x3fff),
        ipv4_captura_incompleta=len(ip) < total,
    )
    if fragmento & 0x1fff:
        return dict(dados, estado="fragmento_sem_cabecalho_transporte")

    transporte = ip[cabecalho:total]
    if protocolo == 6:
        if len(transporte) < 20:
            return dict(dados, estado="tcp_incompleto")
        comprimento = (transporte[12] >> 4) * 4
        if comprimento < 20:
            return dict(dados, estado="tcp_invalido")
        if len(transporte) < comprimento:
            return dict(dados, estado="tcp_incompleto")
        dados["tcp_bytes_cabecalho"] = comprimento
        dados["tcp_flags"] = [
            nome for bit, nome in enumerate(("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"))
            if transporte[13] & (1 << bit)
        ]
    elif protocolo == 17:
        if len(transporte) < 8:
            return dict(dados, estado="udp_incompleto")
        comprimento = unpack_from("!H", transporte, 4)[0]
        if comprimento < 8 or (comprimento > total - cabecalho and not fragmento & 0x2000):
            return dict(dados, estado="udp_invalido")
        dados["udp_bytes_total"] = comprimento
    if protocolo in (6, 17):
        dados["porta_origem"], dados["porta_destino"] = unpack_from("!HH", transporte)
    return dados
