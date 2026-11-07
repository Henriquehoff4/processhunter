# Avisos de Software de Terceiros (Third-Party Notices)

O ProcessHunter integra o motor de sensores profundos usando componentes de código
aberto. Estes componentes são consumidos **sem modificação**, como binários obtidos
pelo gerenciador de pacotes NuGet, e são distribuídos sob suas respectivas licenças.

## LibreHardwareMonitorLib 0.9.6

- Projeto: https://github.com/LibreHardwareMonitor/LibreHardwareMonitor
- Licença: **Mozilla Public License 2.0 (MPL-2.0)** — https://www.mozilla.org/MPL/2.0/
- Uso: leitura de temperatura por núcleo/package, potência RAPL, tensões, RPM de
  ventoinhas e sensores da placa-mãe (Super I/O / Embedded Controller), exibidos na aba
  **Sensores** do ProcessHunter.
- Driver de kernel: a biblioteca embute apenas os módulos (.bin) do
  **PawnIO** (https://github.com/pawnsquad/PawnIO); o driver em si deve estar instalado no Windows e é responsável pelo acesso
  ring-0 a MSR / EC / SMBus. Esse driver só é carregado quando o ProcessHunter é
  executado com privilégios de administrador. Veja o `THIRD-PARTY-NOTICES.txt` do
  projeto LibreHardwareMonitor para a lista completa de componentes e licenças.

### Dependências transitivas (resolvidas automaticamente pelo NuGet)

| Pacote | Versão | Observação |
|---|---|---|
| HidSharp | 2.6.4 | acesso a dispositivos HID |
| DiskInfoToolkit | 1.1.2 | leitura de discos/SMART |
| RAMSPDToolkit-NDD | 1.4.2 | leitura de SPD da memória |
| Mono.Posix.NETStandard | 1.0.0 | abstração POSIX |
| System.IO.Ports | 10.0.3 | portas seriais |
| System.Management | 10.0.2 | WMI |
| System.Threading.AccessControl | 10.0.3 | controle de acesso |

Cada pacote é distribuído sob a licença declarada em seu próprio repositório/NuGet.

## Conformidade com a MPL-2.0

A MPL-2.0 é uma licença de copyleft em nível de **arquivo** (file-level). O ProcessHunter
usa o `LibreHardwareMonitorLib` como dependência binária **não modificada**, o que permite
a distribuição junto de um aplicativo proprietário sem exigir a abertura do código do
ProcessHunter. Caso os arquivos-fonte cobertos pela MPL-2.0 venham a ser modificados, essas
modificações específicas deverão ser disponibilizadas sob os termos da MPL-2.0.
