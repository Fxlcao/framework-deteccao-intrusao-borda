# Reproduzir o cenário misto de 90 segundos

O cenário do TCC foi montado offline com trechos de capturas do CICIoT2023. A entrada do framework é o PCAP misto. O mapa JSON contém os rótulos de referência usados na avaliação após a execução.

## Arquivos necessários

Baixe os PCAPs pelo [site oficial do CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) e coloque as seis partes originais em uma única pasta, mantendo os nomes abaixo. O fundo vem de `BenignTraffic.pcap`, a primeira parte da captura benigna.

| Arquivo | Papel no cenário |
| --- | --- |
| `BenignTraffic.pcap` | Fundo benigno de 90 s, a partir de 120 s após o primeiro registro |
| `DoS-SYN_Flood.pcap` | Episódio aos 10 s |
| `DoS-UDP_Flood.pcap` | Episódio aos 22 s |
| `Recon-PortScan.pcap` | Dois episódios, aos 34 s e 70 s |
| `DDoS-SYN_Flood.pcap` | Episódio aos 46 s |
| `DDoS-UDP_Flood.pcap` | Episódio aos 58 s |

## Montagem offline

Execute a partir da raiz do repositório. A montagem requer Python 3.12 e usa a biblioteca padrão.

~~~powershell
python validacao/montar_misto_90s.py pcap dados/cenario_misto
~~~

O script seleciona os recortes rotulados de um segundo das capturas existentes e realinha seus horários sobre o fundo benigno. Os quadros permanecem com os bytes originais, e os registros são gravados em ordem cronológica. O script confere o SHA-256 do PCAP antes de entregar os arquivos.

- `misto_90s.pcap` com 68.996 registros e SHA-256 `0b032c730b2dc1a8f4894f58ce0aa62ec28c29bde3db0d0ac92ba62e41059bd3`.
- `referencia_misto_90s.json` com os índices e horários de origem, o episódio de cada registro e os subtipos esperados. A primeira entrada em `registros` corresponde ao índice 1 do PCAP.

## Execução e conferência

Instale as dependências e disponibilize o pacote do detector conforme as [instruções do repositório](../README.md#instalação). Para repetir a rodada offline com a versão instalada, execute no Windows com arquivos de saída novos:

~~~powershell
python pipeline/executar_deteccao.py dados/cenario_misto/misto_90s.pcap --perfil-borda --executor nativo --limiar 0.50 --banco dados/cenario_misto/ensaio.sqlite3 --metricas dados/cenario_misto/ensaio.json
~~~

Confirme no JSON de métricas se o executor efetivamente usado foi `nativo`. Para avaliar a detecção, cruze os índices dos pacotes aceitos de cada janela no SQLite com `registros` do mapa. Uma janela é positiva na referência quando contém pelo menos um pacote de episódio rotulado. Na rodada do TCC foram classificadas 6.887 janelas, com 6.194 verdadeiros positivos, 266 falsos positivos, 19 falsos negativos e 408 verdadeiros negativos.
