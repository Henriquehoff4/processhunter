# ProcessHunter — Ultimate System Monitor

ProcessHunter é um gerenciador de processos e monitor de sistema profissional para **Windows 11**, projetado para alto desempenho, precisão de métricas e diagnósticos inteligentes.

---

## Destaques e Funcionalidades

### 1. Monitoramento em Tempo Real de Altíssimo Desempenho
- **CPU**: Utilização total e por núcleo/thread lógico individual (`MultiCoreView`), frequência dinâmica em GHz, contagem de threads e temperatura da zona térmica ACPI (quando disponível no hardware).
- **Sensores Profundos (estilo HWiNFO)**: nova aba "Sensores" com temperatura por núcleo/package, potência RAPL, Vcore, RPM de ventoinhas, tensões e temperaturas da placa-mãe, memória (DIMM) e armazenamento — via motor open-source **LibreHardwareMonitorLib** (MPL-2.0) + driver de kernel **PawnIO** (instalado separadamente). Requer execução como administrador.
- **Memória RAM**: Total física, em uso, disponível, memória comprometida (`Commit Charge` vs `Commit Limit`) e cache do sistema.
- **GPU Especializada (NVIDIA GeForce RTX 4060)**:
  - Integração nativa com **NVIDIA NVML** (`nvml.dll`).
  - VRAM Dedicada (GDDR6) utilizada, livre e total.
  - VRAM Compartilhada em uso.
  - Temperatura em tempo real (°C), potência consumida (Watts) e limite de energia.
  - Clocks da GPU e da memória (MHz).
  - Velocidade da ventoinha (Fan %) e estado de performance (P-State P0–P8).
  - Indicadores de throttling de hardware e software (limite térmico, power cap).
  - Decomposição de motores gráficos Direct3D (`3D`, `Compute`, `VideoDecode`, `VideoEncode`, `Copy`).
  - Tabela de processos em execução na GPU com motores e consumo de VRAM.
- **Armazenamento e Discos**:
  - Taxas reais de leitura e escrita em MB/s.
  - Tempo de atividade do disco (Disk Time %).
  - Tamanho da fila de requisições e latência média em milissegundos.
- **Rede**: Velocidades de download e upload em MB/s e identificação da capacidade máxima de link ativo.
- **Tempo de Atividade (Uptime)**, contagem de processos, threads e handles do kernel.

### 2. Gerenciador de Processos Avançado
- Tabela com virtualização de alta performance para listas com centenas de processos sem engasgos.
- Visualização em **Lista Plana** ou **Árvore Hierárquica** de processos (relação pai-filho / PPID).
- Filtros rápidos por chips: *Todos*, *Aplicativos*, *Segundo Plano*, *Usa GPU*, *Alto Consumo* e *Windows*.
- Pesquisa instantânea por nome, PID, usuário, caminho ou fornecedor.
- Informações completas por processo:
  - Ícone extraído do executável.
  - PID e Parent PID.
  - CPU (%), RAM Privada e Conjunto de Trabalho (Working Set).
  - GPU (%), Motores Gráficos utilizados e VRAM Dedicada.
  - Taxa de E/S de Disco (MB/s).
  - Contagem de Threads e Handles.
  - Prioridade de execução e tempo de atividade contínuo.
  - Usuário responsável (Token de segurança do Windows).
  - Fornecedor e status da Assinatura Digital (Authenticode e catálogos do Windows).
- **Proteção Ativa de Processos Críticos**:
  - Processos essenciais do Windows (`System`, `csrss.exe`, `smss.exe`, `lsass.exe`, `services.exe`, `dwm.exe`, `explorer.exe`, etc.) e o próprio ProcessHunter são estritamente protegidos contra encerramento acidental.
- **Ações**:
  - Finalizar Processo com diálogo de confirmação.
  - Finalizar Árvore de Processos completa.
  - Alterar Prioridade (Alta, Acima do Normal, Normal, Abaixo do Normal, Baixa).
  - Abrir Local do Arquivo no Explorer.
  - Exibir propriedades nativas do executável.
  - Copiar nome, PID e caminho com um clique.

### 3. Detector Inteligente de Gargalos
- Diagnóstico automático e contextual para evitar falsos positivos:
  - **Saturação de CPU e Memória**: alerta quando o sistema está no limite operacional.
  - **Detector de Vazamento de Memória**: análise de regressão linear (R² ≥ 0.85) e monotonicidade ao longo do tempo para detectar crescimento contínuo sem liberação.
  - **VRAM Esgotada**: alerta antes que os dados extravasem para a memória RAM compartilhada (evitando perda brusca de FPS em jogos ou aborto em modelos de IA e After Effects).
  - **Consumo em Segundo Plano**: alerta quando apps não focados mantêm carga anormal.
  - **Carga na Inicialização**: identifica aplicativos que pesaram nos primeiros minutos de boot.
  - **Temperaturas Elevadas**: avisos preventivos para GPU e ACPI.
- **Explicações Contextuais Claras**: diferencia tarefas pesadas intencionais (After Effects, Blender, modelos de IA como Ollama) de defeitos reais, e documenta o comportamento natural de antivírus como o Microsoft Defender (`MsMpEng.exe`).

### 4. Gráficos, Histórico e Análise Comparativa
- Gráficos contínuos em tempo real com renderização direta no DrawingContext (zero latência).
- Histórico gravado localmente em formato compacto JSON Lines (`.jsonl`), com retenção configurável (3, 7, 14 ou 30 dias).
- **Identificação do Culpado em Picos**: ao analisar o histórico, o ProcessHunter indica o processo responsável registrado naquele momento de pico.
- **Comparador Antes e Depois**: capture o estado do sistema antes de abrir um aplicativo e compare com o estado posterior para medir o incremento exato (Δ CPU, Δ RAM, Δ VRAM, Δ GPU e novos processos criados).
- Exportação de relatórios em **CSV** e **JSON**.

### 5. Recursos Extras & Conforto
- **HUD Overlay Compacto**: painel flutuante translúcido, arrastável para qualquer monitor, exibindo CPU, RAM, GPU, VRAM, temperatura e disco.
- **Bandeja do Windows (System Tray)** com menu rápido e notificações automáticas de alertas.
- **Modo Leve Automático**: detecta quando um jogo ou aplicativo 3D em tela cheia assume o primeiro plano e reduz a taxa de amostragem para garantir impacto zero no FPS.
- **Processos Monitorados**: lista de vigilância que avisa imediatamente quando softwares específicos iniciam ou encerram.

---

## Estrutura do Projeto

```
processhunter\
├── src\
│   └── ProcessHunter\           # Projeto Principal (WPF + .NET 8 x64)
│       ├── Collectors\          # Coleta via NtQuerySystemInformation, PDH e NVML
│       ├── Controls\            # Gráficos Sparkline e MultiCoreView
│       ├── Core\                # Motor de Monitoramento, Modelos, Configurações e Histórico
│       ├── Diagnostics\         # Detector de Gargalos e Análise de Vazamento
│       ├── Native\              # Chamadas Win32, NVML e TrayIcon
│       ├── Themes\              # Tema Hunter Dark (Acessibilidade e contraste)
│       └── ViewModels\          # ViewModels do Gerenciador de Processos
├── tests\
│   └── ProcessHunter.Tests\     # Suíte de 26 Testes Rápidos (xUnit, 1s de execução)
├── installer\
│   ├── ProcessHunter.Installer\ # Instalador GUI Standalone (.exe)
│   └── ProcessHunter-Setup.iss  # Script Inno Setup 6
├── publish\
│   ├── portable\                # Versão Portátil (com portable.flag)
│   ├── standalone\              # Executável único autocontido
│   └── installer\               # Instalador executável ProcessHunter-Installer.exe
├── README.md                    # Documentação geral
├── LIMITATIONS_AND_PERMISSIONS.md # Limitações de hardware e permissões
└── THIRD-PARTY-NOTICES.md       # Avisos de software de terceiros (MPL-2.0 etc.)
```

---

## Como Executar

A pasta `publish\` é gerada localmente e não faz parte do repositório. Compile o projeto (veja abaixo) ou baixe os executáveis na aba [Releases](https://github.com/Henriquehoff4/processhunter/releases).

### Versão Portátil (Sem Instalação)
1. Navegue até `publish\portable\` (ou `publish\standalone\`).
2. Execute `ProcessHunter.exe`.
3. Todos os dados e configurações serão salvos localmente na subpasta `.\data\`.

### Instalador Oficial para Windows 11
1. Execute `publish\installer\ProcessHunter-Installer.exe`.
2. Escolha o diretório desejado (padrão: `%LOCALAPPDATA%\Programs\ProcessHunter`).
3. O instalador criará atalhos na Área de Trabalho, no Menu Iniciar e registrará a entrada oficial no painel de Configurações do Windows.

---

## Como Compilar

```
dotnet restore src\ProcessHunter\ProcessHunter.csproj
dotnet publish src\ProcessHunter\ProcessHunter.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

- O pacote **LibreHardwareMonitorLib** (MPL-2.0) é baixado automaticamente pelo `dotnet restore`.
- Para desbloquear os **sensores profundos** (temperatura por núcleo, ventoinhas, tensões),
  execute o ProcessHunter **como administrador** — a aba "Sensores" oferece o botão
  "Reiniciar como Administrador".

---

## Licença

MIT. Veja `LICENSE`. Componentes de terceiros: veja `THIRD-PARTY-NOTICES.md`.
