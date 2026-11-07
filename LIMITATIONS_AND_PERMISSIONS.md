# Documentação Técnica: Limitações de Hardware e Permissões

## 1. Princípio do Menor Privilégio (asInvoker)

O **ProcessHunter** foi arquitetado deliberadamente para operar sob a permissão padrão de usuário (`asInvoker` no manifesto de aplicação `app.manifest`). Isso traz benefícios críticos de segurança e conveniência:
- Não exige aprovação do UAC (Controle de Conta de Usuário) toda vez que o aplicativo é aberto.
- O executável não opera como processo com privilégios desnecessários.
- Elimina o risco de comandos acidentais ou scripts maliciosos explorarem uma ferramenta elevada.

### Impacto nas Permissões:
| Funcionalidade | Sem Administrador (Padrão) | Com Administrador (Opcional) |
|---|---|---|
| **CPU, RAM, Discos, GPU RTX 4060, VRAM** | ✅ 100% Funcional e Preciso | ✅ 100% Funcional |
| **Lista de Processos e Métricas** | ✅ Todos os processos do sistema visíveis via `NtQuerySystemInformation` | ✅ Todos os processos |
| **Finalizar Aplicativos do Usuário** | ✅ Encerra qualquer aplicativo do usuário atual | ✅ Encerra apps de qualquer sessão |
| **Finalizar Processos do Windows (Kernel/System)** | 🛡️ Bloqueado por segurança | 🛡️ Bloqueado por segurança |
| **Caminho e Token de Processos do Sistema** | ⚠️ Exibido como `Kernel` ou `(sem acesso)` para processos de outras contas (ex: LocalSystem) | ✅ Caminho legível para todos |
| **Tráfego de Rede por Processo Individual** | ⚠️ Requer sessão de rastreamento do kernel ETW (Event Tracing for Windows). O total do sistema é 100% lido via PDH. | ℹ️ Requer driver de filtro NDIS ou sessão de rastreamento de rede ETW |

---

## 2. Monitoramento de GPU e NVIDIA NVML

O ProcessHunter integra-se diretamente com a biblioteca oficial **NVIDIA NVML** (`nvml.dll`), instalada automaticamente junto com os drivers GeForce Game Ready ou Studio.

- **GPU Testada e Suportada**: NVIDIA GeForce RTX 4060 (Driver 610.88 / arquitetura Ada Lovelace).
- **Métricas via NVML**:
  - Utilização da GPU (%)
  - Utilização do Controlador de Memória (%)
  - VRAM Total e VRAM Utilizada (Bytes)
  - Temperatura do núcleo (°C)
  - Potência consumida em tempo real (Watts) e Limite de potência configurado
  - Clocks da GPU e da Memória de Vídeo (MHz)
  - Velocidade da ventoinha (Fan %)
  - Utilização dos motores de codificação/decodificação NVENC/NVDEC
  - Motivos de redução de clock / Throttling (Thermal, Power, Reliability)
- **Métricas via Direct3D / DxgKrnl / PDH**:
  - Alocação de VRAM Dedicada e Compartilhada por processo individual.
  - Utilização individual dos motores Direct3D (`3D`, `Compute`, `VideoDecode`, `Copy`).

### Tratamento de Falhas e Transparência:
Caso o ProcessHunter seja executado em uma máquina sem GPU NVIDIA ou com driver incompatível:
1. O NVML faz fallback gracioso para os contadores nativos do subsistema de vídeo do Windows (DxgKrnl via PDH).
2. Se uma métrica específica não for fornecida pelo driver, o aplicativo exibirá explicitamente `—` ou `N/A`.
3. **O ProcessHunter nunca simula nem inventa números fictícios.**

---

## 3. Sensores Térmicos de CPU

- **Visão Geral (sem elevação):** a temperatura de CPU exibida na aba Visão Geral usa a **Zona Térmica ACPI** nativa do Windows (`\Thermal Zone Information(*)\Temperature`), sem nenhum driver.
- **Sensores profundos (aba "Sensores"):** temperatura por núcleo/package, potência RAPL, Vcore, RPM de ventoinhas e sensores da placa-mãe são lidos pelo motor **LibreHardwareMonitorLib** (código aberto, MPL-2.0) com o driver de kernel **PawnIO** (também código aberto). Consulte a seção 5.
- Caso a placa-mãe ou BIOS não exponha sensores térmicos ACPI ao Windows, a métrica da Visão Geral é exibida como `Temp: N/A` ou `— °C`.

---

## 4. Eficiência e Overhead do Monitor

- Ao contrário de ferramentas lentas baseadas em scripts WMI (`Win32_Process`) ou chamadas repetitivas de `Process.GetProcesses()`, o ProcessHunter realiza a coleta de todos os processos do sistema em uma **única chamada de alta velocidade** à API nativa `NtQuerySystemInformation(SystemProcessInformation)`.
- A coleta ocorre em thread dedicada em segundo plano com prioridade `BelowNormal` para nunca competir por recursos com tarefas pesadas do usuário.
- O overhead típico medido é de **0.1% a 0.3% de CPU** e **~30 MB de memória RAM**, sendo exibido com total transparência na barra lateral do aplicativo.
- O recurso **Modo Leve Automático** monitora a janela em primeiro plano: se um jogo ou software 3D em tela cheia estiver ativo, as consultas são espaçadas para assegurar zero impacto na taxa de quadros (FPS) ou no tempo de renderização.

---

## 5. Motor de Sensores Profundos (LibreHardwareMonitorLib + PawnIO)

A aba **Sensores** reimplementa, em código aberto, o mesmo tipo de leitura profunda que
ferramentas como o HWiNFO realizam — sem depender de binários proprietários.

- **Biblioteca:** `LibreHardwareMonitorLib` 0.9.6 (licença **MPL-2.0**).
- **Driver:** `PawnIO` — precisa estar **instalado no Windows** (a biblioteca embute apenas os módulos do PawnIO, não o driver). Sem ele, a aba Sensores avisa que o driver não foi encontrado.
- **Requer elevação:** a leitura ring-0 de MSR (temperatura/potência da CPU), Super I/O e
  Embedded Controller exige **administrador**. Sem ele, o ProcessHunter mantém o `asInvoker`
  e exibe um aviso na aba Sensores com o botão **"Reiniciar como Administrador"**.
- **Sem administrador:** apenas os sensores que não exigem o driver ficam disponíveis (a GPU
  já é lida nativamente via NVML). Nenhum número é inventado — métricas ausentes aparecem como `—`.
- **Compatibilidade do driver:** com a **Integridade de Memória (HVCI/Core Isolation)** ativa,
  o Windows pode bloquear o carregamento do PawnIO, assim como bloqueia outros drivers legados
  de monitoramento. Nesse caso, a aba Sensores informa a indisponibilidade explicitamente.
- **Licenças:** veja `THIRD-PARTY-NOTICES.md` para os avisos completos (MPL-2.0 e dependências).
