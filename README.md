# Agentic Security Scanner

Scanner local para o desafio de AppSec do Mercado Livre. Recebe `BASE_URL`, descobre
recursos da aplicação, tenta autenticação automática quando há credenciais e gera
`findings.json`, inclusive quando não encontra vulnerabilidades.

## Executar

Requisitos: Python **3.9–3.13** (macOS ou Linux), [Ollama](https://ollama.com/download)
instalado e modelo `qwen2.5:3b` baixado. A aplicação-alvo precisa estar acessível
por `localhost` ou IP de loopback. O Ollama e os pesos do modelo não estão no ZIP.

1. Com o Ollama ativo, baixe o modelo uma vez: `ollama pull qwen2.5:3b`.
   Se precisar iniciar o serviço manualmente, use `./scripts/start-ollama.sh`
   em outro terminal.
2. Na pasta extraída do projeto, execute:

   ```sh
   BASE_URL=http://localhost:3000 ./run.sh
   ```

Se o alvo exigir login, defina `CHALLENGE_USERNAME` e `CHALLENGE_PASSWORD` no
ambiente antes de executar. O scanner aceita formulários HTML POST/CSRF, HTTP Basic
e um subconjunto de login JSON descoberto na aplicação.

Em computadores onde o Ollama falha por falta de memória de GPU, use
`BASE_URL=http://localhost:3000 ./run.sh --cpu`. Esse modo inicia um Ollama CPU
temporário e exige o executável `ollama` no `PATH`. O modelo `qwen2.5:7b` sugerido
pelo desafio pode ser usado via `OLLAMA_MODEL=qwen2.5:7b`; o padrão 3B foi escolhido
por ter funcionado de modo mais estável na máquina de validação.

O primeiro `run.sh` cria `.venv` e instala as dependências de `vendor/` **sem
internet**. Os wheels incluídos cobrem macOS Apple Silicon e Linux x86-64 com
glibc. Em outra plataforma, execute `./setup.sh --online` antes do scan. Se a
extração do ZIP remover a permissão de execução, aplique
`chmod +x run.sh setup.sh test.sh scripts/start-ollama.sh`.

## O que é verificado

| Verificação | Critério para achado |
|---|---|
| CPF em resposta HTTP | Contexto de CPF, 11 dígitos e verificadores válidos; exemplos conhecidos são filtrados. |
| HTTP method tampering | GET protegido negado sem sessão, mas POST anônimo devolve o mesmo conteúdo protegido em duas tentativas, com controles negativos. |
| Extras | Flags de cookie de sessão, reutilização após logout e redirecionamento externo controlável, sempre com controles de confirmação. |

O relatório `findings.json` contém o tipo, local, evidências, impacto, remediação
e limitações de cada achado. `status: completed` significa que o fluxo terminou
dentro dos limites observados; `partial` indica cobertura incompleta. **Zero
achados não prova que a aplicação é segura.** Códigos de saída: `0` concluído,
`3` parcial, `2` erro e `130` interrupção. Dados sensíveis são mascarados.

## Arquitetura

`run.sh` prepara o ambiente; `main.py` coordena descoberta, autenticação,
verificações e relatório. `discovery.py` e `scanner/surface.py` extraem links,
formulários e referências explícitas. O Ollama local (`scanner/agent.py`) prioriza
IDs descobertos e escolhe campos de login; o código valida essas escolhas e
`scanner/detectors.py` confirma os achados. URLs e campos inventados pela IA são rejeitados; ela não declara
vulnerabilidades. `scanner/network.py` limita requisições, tempo e tamanho das
respostas; `scanner/report.py` valida, mascara e grava o JSON atomicamente.

Por segurança, o scanner aceita apenas loopback, mantém as requisições na mesma
origem e não segue redirecionamentos externos. Não executa JavaScript, não cobre
MFA/SSO e confirma method tampering apenas no caso GET→POST. Conteúdo dinâmico
pode resultar em teste inconclusivo. O PDF confidencial do desafio não está no ZIP.

## Validar

```sh
./test.sh              # suíte automatizada; não requer modelo
./test.sh --live --cpu # também testa Ollama real e scans vulnerável/protegido
```

O teste vivo requer `ollama` no `PATH` e `qwen2.5:3b` já baixado. Para usar um
serviço Ollama que já funciona, execute `./test.sh --live`. Os testes vivos
substituem `findings.json` pelos relatórios dos cenários de teste.

Detalhes de resultados e limites: [validação](docs/validacao.md),
[matriz de requisitos](docs/requisitos.md) e [guia técnico](docs/guia-tecnico.md).
O schema do relatório está em [schemas/findings.schema.json](schemas/findings.schema.json).
