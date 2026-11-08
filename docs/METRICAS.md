# Métricas operacionais

Use o comando do framework com --metricas e indique o caminho de um arquivo JSON novo.

```powershell
python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --limite 100 --metricas "$PWD\metricas.json"
```

O relatório registra a configuração, o ID da execução, os hashes dos artefatos, o tempo de carga do modelo, as contagens de eventos, a vazão, a CPU média e o pico de memória física do processo no Windows. A CPU usa um núcleo como referência, portanto pode ultrapassar 100% quando há trabalho em paralelo. CPU e memória incluem a inicialização.

A vazão divide as contagens pelo tempo operacional, incluindo a saída JSONL e a drenagem do gravador no encerramento. Cada janela também recebe tempos_ms na saída JSONL.

A medida janela_processamento_ate_decisao soma a leitura e o preparo dos pacotes, a chamada ao executor, a validação com contexto em memória e a decisão. A leitura pode incluir descartes entre janelas. O total exclui inicialização, enfileiramento, SQLite, saída JSONL e os intervalos originais da captura. A contagem até 1 ms usa essa medida nas janelas classificadas. A inferência inclui a preparação interna do executor do Uller.

As distribuições consideram apenas as janelas classificadas. A média e o máximo usam todas essas janelas. Os percentis usam todas até 10 mil janelas e uma amostra uniforme de 10 mil quando o total ultrapassa esse limite. Janelas inválidas aparecem na saída e nas contagens, sem entrar nos percentis.

O bloco persistencia_assincrona informa os tempos de enfileiramento, gravação e drenagem, o número de lotes, eventos e resultados confirmados e o pico de fila observado. Também conta contextos enfileirados antes da inferência e os adiados por saturação. O tempo de enfileiramento soma as duas entregas quando aplicável. O tempo do gravador se sobrepõe ao processamento. A fila tem capacidade limitada e, se saturar, o produtor espera por espaço.

Compare cenários usando a mesma configuração, destino de saída e política de armazenamento. Para avaliar a meta, faça rodadas repetidas e declare quais etapas estão incluídas no orçamento de 1 ms.
