# Tipagem de ataques

O detector do Uller continua binário. A entrada e o limiar do modelo são independentes das regras de subtipo. Validação e Classificação observa o contexto dos pacotes das janelas válidas, inclusive benignas, para manter o histórico de rede. Um subtipo só é atribuído quando o detector classifica a janela como ataque.

- syn_flood: duas janelas consecutivas de ataque, cada uma com pelo menos 8 SYN sem outras flags ao mesmo IPv4 e porta TCP de destino, em até 8 ms por grupo e entre os grupos.
- udp_flood: pelo menos 100 datagramas UDP completos e não fragmentados para o mesmo IPv4 de destino em até 100 ms, com pelo menos 5 datagramas desse grupo na janela atual. A porta pode variar.
- port_scan: pelo menos 20 portas TCP distintas observadas em SYN sem outras flags, para o mesmo par IPv4 origem e destino em até 1 s, com pelo menos 3 portas diferentes para o par na janela atual.

As contagens de 100 datagramas e 20 portas indicam os limiares atingidos. O histórico mantém até 128 grupos por mecanismo e reinicia entre capturas independentes, em interrupções e quando o relógio da captura regride nas evidências observadas. Regras concorrentes ou insuficientes deixam o subtipo indeterminado. O tipo e a evidência são registrados na classificação, no alerta local e no SQLite. Os valores são experimentais e precisam ser avaliados com dados de teste separados dos trechos que motivaram as regras.

O nome do PCAP não participa da classificação. A distinção DoS/DDoS fica no cenário de referência, pois a regra observa o mecanismo e o alvo, não a quantidade de atacantes confirmados. A comunicação entre nós conserva o contrato atual de notificação binária.
