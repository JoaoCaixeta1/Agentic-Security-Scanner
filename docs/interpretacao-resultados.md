# Como interpretar os resultados das verificações

`completed` descreve o término do fluxo, não um atestado de segurança do alvo.
Cada item de `checks` contém os contadores e os motivos abaixo. `details` registra
até 100 observações por detector, com URLs mascaradas e IDs das requisições.
`reasons` agrega os motivos mesmo quando o limite de detalhes é atingido.

| Campo | Significado |
|---|---|
| `tested` | Unidades analisadas: respostas, recursos, cookies ou fluxos, dependendo do detector |
| `confirmed` | Achados novos, após deduplicação, que satisfizeram os critérios do detector |
| `negative` | Não foi observada a condição vulnerável específica no controle analisado |
| `inconclusive` | Evidência ausente, resposta ambígua, truncada ou controle que não se reproduziu |
| `skipped` | Verificação não executada por falta de pré-requisito, candidato suportado ou política |

Os contadores não são uma partição exata de `tested`: achados são deduplicados e
um motivo de `skipped` pode resumir a ausência de candidatos de todo o scan.
Resultados negativos não comprovam ausência de outras vulnerabilidades.

## Motivos mais importantes

| Código em `reasons` | Interpretação |
|---|---|
| `no_contextual_valid_cpf` | Não foi encontrado CPF com checksum e contexto exigidos na resposta analisada |
| `json_traversal_limit` | Limites de profundidade, quantidade de campos/itens ou nós impediram a análise completa do JSON; ausência de achado é inconclusiva |
| `invalid_json` / `body_truncated` | Não foi possível analisar o conteúdo completo de forma confiável |
| `post_did_not_bypass_access_control` | Os dois POSTs anônimos foram negados (inclusive por retorno ao login), ou receberam 405; o GET de controle continuou negado |
| `anonymous_denial_not_reproduced` | O controle anônimo não demonstrou a restrição esperada |
| `post_response_not_comparable_or_control_failed` | O POST não reproduziu o conteúdo protegido, mas também não houve evidência suficiente para um resultado negativo controlado |
| `applicable_cookie_flags_present` | Cookie inspecionado tem HttpOnly e, se HTTPS, Secure; não significa que o papel de autenticação desse cookie foi provado |
| `cookie_authentication_role_not_proven` | Falta uma flag, mas os controles não demonstraram que o cookie é necessário e suficiente para a autenticação |
| `no_cookies` / `cookie_limit` | Não havia cookies, ou o limite de cookies por verificação foi atingido |
| `old_session_rejected_after_logout` | Logout verificado e duas reutilizações independentes do cookie antigo retornaram negação de acesso |
| `logout_effect_not_verified` | Não foi possível comprovar que o logout realmente encerrou a sessão atual |
| `old_session_response_not_comparable_or_control_failed` | A reutilização não comprovou acesso nem negação estável |
| `no_supported_logout_discovered` | Não foi descoberto um link/formulário de logout utilizável |
| `non_cookie_authentication` | O teste de logout por cookie não se aplica à autenticação Basic/Bearer observada |
| `no_supported_destination_parameter` | Não foram descobertos parâmetros contendo URLs/caminhos internos; IDs numéricos e redirects JavaScript não são testados |
| `baseline_not_http_redirect` | O candidato não produziu redirect HTTP com Location |
| `baseline_destination_outside_scope` | O destino original já era externo; o scanner não o seguiu |
| `public_redirector_intent_unknown` | Um redirect público pode ser intencional; não foi confirmado como vulnerabilidade |
| `external_redirect_not_reproduced` | As duas variações não confirmaram controle do destino externo |
| `no_authenticated_session` / `no_stable_protected_reference` | Faltou sessão ou conteúdo protegido estável para comparar |
| `unsafe_resource` | A política de ações impediu o teste nesse recurso |

## Redirecionamentos nos controles de autenticação

A aplicação pode negar acesso com 302 para um formulário de login, em vez de 401
ou 403. O scanner segue apenas redirects permitidos pelo gateway e identifica o
formulário no destino. Um status 200 na página de login não significa acesso
concedido. Redirects externos e reenvio de POST em 307/308 continuam bloqueados.

No teste de logout, cada repetição restaura a mesma cópia antiga do cookie. Isso
impede que um cookie anônimo recebido na primeira tentativa contamine a segunda.


## Falhas operacionais

Alvo desconectado, Ollama indisponível e autenticação não verificada com
credenciais fornecidas deixam o scan parcial. Respostas HTTP 5xx durante a
descoberta ou login também registram aviso de cobertura incompleta e tornam o
resultado parcial. A resposta ainda é inspecionada, pois páginas de erro podem
conter dados expostos; o aviso não apaga evidências já coletadas.

Isso difere de uma resposta 5xx produzida por uma sonda do detector: nesse caso,
o controle específico pode ser inconclusivo, conforme seus critérios. O status
`completed` nunca significa que toda vulnerabilidade possível foi descartada.
