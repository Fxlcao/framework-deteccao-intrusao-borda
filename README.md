# Framework de detecção de intrusões na borda

Protótipo desenvolvido como Trabalho de Conclusão de Curso por Leandro Esser Falcão. O framework processa capturas de tráfego IoT em um nó de borda e registra decisões e alertas localmente. A avaliação experimental usa arquivos PCAP do CICIoT2023, cargas com restrição de recursos e reprodução temporal em laboratório.

## Como funciona

[Diagrama completo do framework](docs/DIAGRAMA_FRAMEWORK.md)

~~~text
PCAP → Pré-processamento → Detecção binária → Validação e tipagem → Decisão local
             │                                       │                  │
             └─────────────────────────→ Gravador assíncrono ←──────────┘
                                                    │
                                                  SQLite
~~~

1. O pré-processamento lê PCAP clássico 2.4 com quadros Ethernet, interpreta os registros aceitos e forma janelas de dez pacotes. A extração gera 36 atributos e mantém referências aos registros de origem.
2. O detector binário LightGBM, desenvolvido por Victor Uller, recebe os 30 atributos de inferência em `float32`, na ordem do contrato. O campo `Number` valida o tamanho da janela.
3. O framework confere o resultado binário e usa o contexto em memória para tipar janelas sinalizadas. As regras cobrem `syn_flood`, `udp_flood` e `port_scan`. Evidência insuficiente ou concorrente deixa o subtipo indeterminado.
4. A decisão local registra um alerta para cada janela sinalizada. O gravador SQLite recebe o contexto e o resultado por uma fila limitada. O encerramento normal aguarda a confirmação da escrita.
5. A revisão supervisionada e a troca de alertas entre processos são operações separadas sobre os resultados persistidos. A revisão permite exportar janelas confirmadas e avaliar limiares. O ensaio de comunicação usa HTTP em loopback com um token definido no ambiente.

## Instalação

O ambiente usado na validação foi Windows com Python 3.12. O pré-processamento isolado usa somente a biblioteca padrão do Python.

~~~powershell
git clone https://github.com/Fxlcao/framework-deteccao-intrusao-borda.git
Set-Location framework-deteccao-intrusao-borda
~~~

Para a detecção completa, instale as versões do pacote do modelo e obtenha os seguintes insumos.

- **Captura PCAP.** Baixe as capturas pela página oficial do [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html). Nos exemplos, `pcap/BenignTraffic.pcap` é o caminho local da captura benigna.
- **Pacote do detector.** Obtenha com Victor Uller a versão compatível do pacote LightGBM, que inclui `ids_modelo.py`, `contrato.json`, `modelo.joblib` e `exemplo_conformidade.csv`. Mantenha os arquivos juntos. O exemplo usa `algoritimo.Att/pacote_modelo`, o caminho padrão do executor. Use `--modelo` para indicar outra pasta. Os binários e as amostras do detector são distribuídos separadamente pelo autor.

No PowerShell, a partir da raiz do repositório:

~~~powershell
python -m venv .venv
$python = ".\.venv\Scripts\python.exe"
& $python -m pip install -r requirements.txt
& $python "algoritimo.Att/pacote_modelo/ids_modelo.py" --conferir
~~~

Carregue o `modelo.joblib` somente de uma fonte em que você confia. O verificador do pacote deve indicar conformidade antes do primeiro ensaio.

## Execução

### Pré-processamento isolado

~~~powershell
python pipeline/processamento/processar_pcap.py "pcap/BenignTraffic.pcap" > janelas.jsonl
~~~

Cada linha registra uma janela completa ou incompleta, um pacote rejeitado, um erro de leitura ou um resumo do arquivo. A comparação com CSVs produzidos pelo extrator de referência do CIC pode ser feita com `pipeline/processamento/validar_processamento.py`. O script recebe uma pasta com `piloto_benigno.pcap`, `piloto_ddos_syn.pcap`, `referencia_benigno.csv` e `referencia_ddos_syn.csv`. Os CSVs devem corresponder aos PCAPs usados no teste, com janelas de dez pacotes.

### Detecção, classificação e armazenamento

~~~powershell
$python = ".\.venv\Scripts\python.exe"
New-Item -ItemType Directory -Path dados -Force | Out-Null
& $python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --modelo "algoritimo.Att/pacote_modelo" --limite 5000 --perfil-borda --banco "dados/piloto.sqlite3" --metricas "dados/piloto-metricas.json" > dados/piloto-eventos.jsonl
~~~

| Parâmetro | Uso |
| --- | --- |
| `pcaps` | Um ou mais caminhos PCAP. Por padrão, o contexto reinicia entre capturas. |
| `--continuo` | Preserva o contexto entre partes consecutivas da mesma captura, na ordem fornecida. Exige leitura integral de cada parte. |
| `--limite N` | Limita a leitura a `N` registros por arquivo. |
| `--modelo PASTA` | Seleciona o pacote local do detector. |
| `--executor` | Seleciona `nativo`, `simplificado` ou `original`. O padrão é `nativo`, com verificação de conformidade e alternativas de compatibilidade. |
| `--limiar` | Ajusta o limiar binário apenas para a execução atual. O pacote de referência usa 0,5. |
| `--perfil-borda` | Aplica no Windows um orçamento de duas CPUs lógicas e 1.024 MiB de memória comprometida para o processo. Os parâmetros `--cpu-logicas` e `--memoria-mib` permitem variar o perfil. |
| `--banco` | Define o arquivo SQLite. Para comparar rodadas independentes, use um banco por rodada. |
| `--metricas` | Gera o relatório JSON. Informe o caminho de um arquivo novo a cada rodada. |

A saída JSONL registra os eventos e, para as janelas processadas, a predição, a classificação e a decisão local. O SQLite mantém os eventos, o contexto, as decisões e a identificação da execução. O relatório inclui o executor efetivamente usado, o perfil de recursos, os hashes do pacote, os tempos por etapa, a vazão e as estatísticas do gravador.

## Validação experimental

O [guia do cenário misto de 90 segundos](docs/CENARIO_MISTO_90S.md) lista os seis PCAPs de origem e mostra como reconstruir o arquivo misto e o mapa de referência para repetir o ensaio offline.

| Ensaio | Resultado registrado no TCC |
| --- | --- |
| PCAP misto de 89,99 s, processado offline | 68.996 registros, 6.887 janelas classificadas e seis episódios sinalizados. Cada episódio teve pelo menos uma janela com subtipo correto. A taxa de falsos positivos por janela de referência negativa foi de 39,5%. |
| Controle benigno offline | 17.789 de 29.405 janelas foram sinalizadas (60,5%). |
| Carga offline de 300 mil registros, duas CPUs lógicas e 1.024 MiB | p95 local entre 0,617 e 0,757 ms nas três rodadas com a versão final. |
| Carga offline de 600 mil registros, uma CPU lógica e 512 MiB | A variante final reduziu o tempo operacional mediano de 80,53 para 62,93 s em relação à variante de referência. A mediana do p95 local foi de 1,211 ms na variante final. |
| Reprodução temporal do PCAP misto em laboratório | O p95 a partir da entrega efetiva do décimo pacote até a decisão foi de 1,10 ms a 1× e 1,00 ms a 2×. A espera pela formação da janela e o atraso de entrega são medidas separadas. |

O **p95 local** do processamento offline mede o tempo acumulado de leitura e preparo, inferência, validação e classificação, e decisão. A métrica exclui a inicialização, a espera pelos intervalos originais do tráfego, o enfileiramento, a gravação SQLite e a saída JSONL. O **tempo operacional** abrange a execução do fluxo, incluindo a emissão dos eventos e a drenagem do gravador. O relatório separa a carga inicial do modelo.

A meta de 1 ms refere-se à latência local medida sob as condições do ensaio. Os resultados caracterizam um protótipo em laboratório, com PCAPs de tráfego IoT e limites impostos ao processo no Windows. A espera pelos pacotes, a taxa de alertas no controle benigno e o comportamento sob carga restrita são relevantes ao interpretar a implantação em uma rede real.

## Documentação dos módulos

- [Executor LightGBM](docs/EXECUTOR_LIGHTGBM.md)
- [Tipagem de ataques](docs/TIPAGEM_DE_ATAQUES.md)
- [Validação, classificação e armazenamento](docs/VALIDACAO_E_ARMAZENAMENTO.md)
- [Decisão e alertas](docs/DECISAO_E_ALERTAS.md)
- [Métricas operacionais](docs/METRICAS.md)
- [Perfil de recursos de borda](docs/PERFIL_DE_BORDA.md)
- [Retroalimentação e comunicação entre nós](docs/RETROALIMENTACAO_E_COMUNICACAO.md)

## Créditos

- **Framework e avaliação experimental:** Leandro Esser Falcão.
- **Detector binário LightGBM e contrato de entrada:** Victor Uller.
- **Dados de referência:** Canadian Institute for Cybersecurity, University of New Brunswick. [CICIoT2023 e documentação oficial](https://www.unb.ca/cic/datasets/iotdataset-2023.html).
