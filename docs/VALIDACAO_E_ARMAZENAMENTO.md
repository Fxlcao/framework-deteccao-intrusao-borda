# Validação e classificação com armazenamento

```powershell
python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --limite 100
```

A execução grava no SQLite em dados/framework.sqlite3. Use --banco seguido de outro caminho para separar experimentos. Cada rodada recebe um identificador próprio. O banco mantém as rodadas até que seja definida uma política de retenção.

Assim que uma janela válida é formada, seu contexto é disponibilizado em memória e enfileirado para gravação em segundo plano. O detector começa sem aguardar a confirmação no SQLite. A validação recupera o contexto da janela em memória pelo ID, mesmo durante a gravação. O resultado e a decisão são enfileirados depois e associados ao mesmo ID. Se a fila estiver cheia antes da inferência, a entrega do contexto ao gravador é adiada e feita junto com o resultado.

A tabela execucoes registra a configuração e os hashes SHA-256 do contrato, executor e modelo. A tabela eventos conserva as janelas, rejeições, erros de leitura e resumos. Uma janela guarda as referências aos pacotes, que continuam no PCAP original.

Consulta de uma janela por ID em qualquer visualizador SQLite:

```sql
SELECT contexto, deteccao, classificacao
FROM eventos
WHERE id = 'ID_DO_EVENTO';
```

O gravador SQLite usa uma fila limitada e confirma lotes em segundo plano. Uma saída JSON indica processamento concluído; a confirmação no banco pode ocorrer depois. O encerramento normal aguarda a drenagem. Uma falha no gravador é reportada como erro da execução. Uma interrupção abrupta pode perder eventos ainda não confirmados.
