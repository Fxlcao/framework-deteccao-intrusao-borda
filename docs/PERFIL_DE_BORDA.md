# Perfis de recursos para o nó de borda

O parâmetro --perfil-borda limita o processo do framework a duas CPUs lógicas e 1.024 MiB de memória comprometida. O Windows aplica os limites antes da carga do modelo, incluindo a inferência e a thread de persistência. Para definir outro orçamento, use --cpu-logicas e --memoria-mib.

```powershell
python pipeline/executar_deteccao.py "pcap/BenignTraffic.pcap" --perfil-borda --limite 5000 --banco "$PWD\piloto-borda.sqlite3" --metricas "$PWD\piloto-borda.json"
```

O Raspberry Pi 4 Model B oferece quatro núcleos Cortex-A72 e configurações de memória a partir de 1 GB. O orçamento de duas CPUs lógicas e 1 GiB foi escolhido como cenário de restrição para a aplicação. O cenário de uma CPU lógica e 512 MiB representa uma condição mais severa. Os perfis não são médias de dispositivos e não reproduzem a frequência, a arquitetura ARM, o sistema operacional ou o armazenamento de uma placa física.

O relatório contém a afinidade aplicada, o pico de memória comprometida, o pico de memória física residente, a vazão, as latências e o tamanho e crescimento do arquivo principal do SQLite. O teto de memória é do processo, não de todo o computador. O tamanho do SQLite é observado após a drenagem e não constitui uma cota de disco. Para comparar perfis use recortes, configuração, modelo e destino de saída equivalentes, com banco novo em cada rodada.

Referências:
- Raspberry Pi 4 Model B: https://www.raspberrypi.com/documentation/computers/sbcs.html
- Limites de Job Objects: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
