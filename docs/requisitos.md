# Conferência dos requisitos do desafio

Esta matriz relaciona os requisitos do enunciado à implementação. Evidência de
funcionamento em nossos testes não garante cobertura da aplicação privada dos
avaliadores. O documento confidencial original não integra a entrega.

| Requisito | Implementação e evidência | Limites |
|---|---|---|
| Entrada BASE_URL via run.sh | Bootstrap offline e execução pelo shell; testes vivos usam run.sh | Python 3.9–3.13, macOS/Linux; demais pré-requisitos no README |
| Crawling | Links, formulários, referências JSON/OpenAPI e referências literais em scripts | Não executa JavaScript; limites de páginas, profundidade e requisições |
| Login automático por credenciais de ambiente | Formulários POST/CSRF, Basic e subconjunto de login JSON/Bearer; controle anônimo verifica autenticação | Sem MFA, CAPTCHA, SSO ou JavaScript dinâmico |
| CPF em respostas | Contexto de campo/rótulo, checksum, filtros de exemplos e mascaramento do relatório | Checksum não prova pessoa real nem acesso indevido; revisão humana necessária |
| HTTP method tampering | GET protegido contra POST anônimo, duas reproduções e controles negativos | Subconjunto do requisito: confirmação de bypass GET→POST; não cobre todas as combinações de métodos ou intenção de negócio |
| IA local via Ollama | Planejamento limitado a IDs/campos descobertos, schema e validação posterior | qwen2.5:3b padrão; 7b opcional. Modelo não confirma vulnerabilidades |
| Execução local, sem alvo externo | Escopo loopback e mesma origem; redirects validados; proxy ambiente desativado | Ollama e pesos devem ser instalados antes; scan não baixa modelos |
| Sem caminhos/conhecimento específico do alvo | Descoberta genérica; fixtures com rotas aleatórias; DVWA separado | Nomes genéricos de campos de login são heurísticas, não catálogo de endpoints |
| findings.json mesmo sem achados | Relatório estruturado, status e erros; testes de cenário protegido e configuração inválida | Escrita exige diretório gravável e espaço disponível |
| Explicar achado, local e impacto | Tipo, URL mascarada, evidência, severidade, confiança, impacto, remediação e limites | Valores sensíveis são omitidos; nem todo erro de negócio pode ser confirmado automaticamente |
| Controle de consumo | Limites de chamadas/tokens, tempo, respostas, páginas e requisições | CPU pode aumentar a duração; interrupção deve ser tratada como parcial |
| README e ZIP | README documenta arquitetura, operação e decisões; ZIP com verificação de integridade, permissões e conteúdo | Ollama e modelo local são pré-requisitos; envio manual |

## Estado da entrega

- Rodada limpa concluída: 159 testes regulares, dois scans com IA real e rejeição de alvo externo pelo CLI aprovados.
- ZIP extraído e validado com dependências offline, Ollama real, cenários positivo/negativo e DVWA local.
- Limitações de method tampering, autenticação e JavaScript documentadas.
- O envio por email permanece manual, conforme as instruções do processo seletivo.
