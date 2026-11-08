# Execução do detector LightGBM

O adaptador usa o mesmo modelo do Uller. Ele confere a ordem dos atributos com o contrato e com o modelo, valida a quantidade de pacotes pelo campo Number e prepara um vetor float32. A classe usa a probabilidade antes do arredondamento.

O modo padrão, `--executor nativo`, reutiliza a configuração de predição de uma linha do LightGBM, com uma thread. A ativação exige que a saída dos exemplos de conformidade coincida com a do modo simplificado antes do arredondamento. Se a API ou o modelo forem incompatíveis com esse caminho, o programa usa o modo simplificado, que chama Booster.predict. Caso o adaptador simplificado também seja incompatível, o programa usa o executor original do pacote.

O modo efetivamente usado fica no relatório de métricas e no SQLite. Use `--executor simplificado` para usar o caminho anterior de inferência ou `--executor original` para usar o executor fornecido pelo Uller.

```powershell
python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --perfil-borda --limite 100 --executor nativo
```

A interface entrega a decisão binária, a probabilidade de ataque e a validade da janela ao módulo de Validação e Classificação.
