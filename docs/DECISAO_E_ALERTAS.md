# Decisão e alertas

A política local alerta para cada janela classificada como ataque. A prioridade é normal por padrão. A probabilidade do detector é incluída como informação de apoio, sem servir de medida da gravidade. Janelas benignas e entradas inválidas recebem uma decisão registrada sem alerta. Eventos de leitura e janelas incompletas continuam no relatório do processamento.

O alerta aparece em decisao.alerta na saída JSONL. Ele inclui um ID, a janela de origem, horário UTC, probabilidade e contexto. O campo tipo_ataque recebe o resultado da tipagem do framework. Quando a evidência é insuficiente, fica nulo.

A tabela decisoes vincula a decisão à janela registrada em eventos. A decisão é persistida junto com a detecção e a classificação. O contexto da janela pode já estar no SQLite, pois é encaminhado ao gravador antes da inferência. A tabela é criada automaticamente em bancos existentes.

```powershell
python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --limite 100
```

A saída local pode ser redirecionada para um arquivo JSONL. Use --banco para selecionar o banco do experimento. O envio externo, a correlação entre janelas, a mitigação e as métricas experimentais são etapas separadas.
