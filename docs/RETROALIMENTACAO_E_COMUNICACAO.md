# Retroalimentação e comunicação entre nós

## Retroalimentação

A revisão referencia uma janela válida já gravada e registra classe confirmada, responsável e evidência. Cada revisão é armazenada. A exportação usa a revisão mais recente por janela e conserva os atributos, as referências ao PCAP e os hashes do detector usado. Janelas sem revisão ficam fora do conjunto exportado.

```powershell
python pipeline/retroalimentacao.py --banco ".\experimento.sqlite3" rotular ID_JANELA benigno --responsavel "Nome" --referencia "Evidência da revisão"
python pipeline/retroalimentacao.py --banco ".\experimento.sqlite3" exportar ID_EXECUCAO ".\janelas_revisadas.jsonl"
python pipeline/retroalimentacao.py --banco ".\experimento.sqlite3" avaliar ID_EXECUCAO --limiares 0.5 0.4
```

A avaliação calcula TP, TN, FP e FN a partir dos rótulos revisados e das probabilidades já armazenadas com o arredondamento do executor. O resultado auxilia a escolha de um limiar. A opção --limiar aplica a escolha somente à execução em que foi indicada e o valor fica registrado. Use dados independentes da calibração para avaliar o limiar escolhido.

A atualização do modelo ocorre com a substituição controlada do pacote da execução por --modelo, após o teste de conformidade do pacote candidato. O LightGBM permite refit e continuação do treinamento com exemplos e rótulos. Neste recorte, o retreinamento é externo ao fluxo online e as previsões e os alertas de vizinhos permanecem separados dos rótulos confirmados.

## Comunicação

O envio é uma operação separada sobre alertas já persistidos. O JSON identifica origem, destino, alerta, horário, ação de notificação e probabilidade. O alvo da mitigação permanece indeterminado. A mensagem contém a referência de janela e omite os atributos e caminhos locais dos PCAPs.

O receptor de teste escuta somente em 127.0.0.1. Em dois terminais no mesmo computador, defina o mesmo token forte em FRAMEWORK_TOKEN_NOS e execute:

```powershell
python pipeline/comunicacao_nos.py --banco ".\receptor.sqlite3" --origem borda --no receptor receber --porta 8765
```

```powershell
python pipeline/comunicacao_nos.py --banco ".\experimento.sqlite3" --origem borda --no receptor enviar ID_EXECUCAO "http://127.0.0.1:8765/alertas"
```

O receptor valida token, esquema, origem, destino, atualidade do envio e identidade da mensagem. Reenvios idênticos recebem confirmação sem novo registro. IDs reutilizados com conteúdo diferente geram conflito. A decisão local registra o evento para análise. A tabela comunicacao_envios guarda duração em ms, bytes do corpo JSON e resultado de cada tentativa. A tabela comunicacao_recebida guarda as mensagens aceitas e a decisão local. Em laboratório, use apenas loopback. A operação remota exige configurar um receptor acessível via HTTPS, credenciais e política de rede.

Referências: documentação de Booster.refit e lightgbm.train do LightGBM e RFC 4765 sobre identificação e conteúdo de alertas. O contrato JSON é próprio do protótipo.
