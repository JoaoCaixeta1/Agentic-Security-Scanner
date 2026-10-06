# Validação da versão atual

O challenge exige um scanner local que aceite `BASE_URL`, faça crawling, tente
login com `CHALLENGE_USERNAME`/`CHALLENGE_PASSWORD`, use Ollama local e produza
`findings.json` inclusive sem achados. Os detectores obrigatórios são CPF em
respostas HTTP e HTTP method tampering. Os extras mantidos são flags de cookie,
sessão após logout e open redirect. A IA prioriza e ajuda a escolher campos de
login; regras em código autorizam requisições e confirmam achados.

## Resultados verificáveis

| Cenário | Cobertura e resultado | Interpretação |
|---|---|---|
| Fixtures HTTP com rotas aleatórias + Ollama 3B real | `./test.sh --live --cpu`: 2 scans aprovados, cinco tipos de achado no vulnerável e zero no protegido | Verifica detecções positivas e controles negativos em aplicações controladas; não mede recall em alvos inéditos |
| DVWA `low` (repetido do ZIP extraído) | `completed`, login verificado, 56 páginas, 390 requisições, 3 decisões válidas; cookie sem HttpOnly e open redirect | 25 recursos protegidos negaram GET→POST; 55 respostas não continham CPF contextual válido |
| DVWA `impossible` | `completed`, login verificado, 291 requisições, zero achados, sem erros ou avisos | 15 recursos negaram GET→POST; cookies tinham flags aplicáveis e cookie antigo foi rejeitado após logout |
| OWASP Juice Shop | `partial`, 4 recursos, zero achados, login não tentado | Interface Angular sem links/formulários HTML observáveis; a cobertura dinâmica foi explicitamente marcada como parcial |
| OWASP Mutillidae II | `partial`, 134 páginas, 191 requisições, zero achados; sessão observada mas sem recurso protegido estável | CPF verificado em 135 respostas; GET→POST e checks de sessão ficaram pulados; oito candidatos a redirect inconclusivos |

Relatórios das fixtures: `docs/exemplos/vulneravel.json` e
`docs/exemplos/protegido.json`. Relatórios externos: `docs/exemplos/dvwa-low-optimized.json`,
`docs/exemplos/dvwa-impossible-optimized.json`,
`docs/exemplos/juice-shop-partial.json` e
`docs/exemplos/mutillidae-partial.json`. As URLs são de containers locais de
laboratório, não da aplicação privada dos avaliadores. O DVWA foi restaurado ao
padrão `low` ao fim da comparação. Juice Shop e Mutillidae foram parados.

A execução limpa da versão atual instalou dependências offline em ambiente
virtual novo e aprovou **159 testes regulares e 2 scans com Ollama real**. A fixture
vulnerável terminou `completed` com cinco tipos de achado; a protegida terminou
`completed` sem achados. Também foi rejeitado um alvo externo com código 2 e JSON
válido. Isso ocorreu após a correção de redação. O DVWA `impossible` e o
Mutillidae também foram repetidos com essa correção.

Uma cópia extraída do ZIP de revisão instalou as dependências a partir de `vendor/`,
passou novamente os **159 testes e 2 scans com Ollama real**, rejeitou um alvo
externo com JSON válido e executou o DVWA `low`: `completed`, login verificado,
56 páginas, 390 requisições, dois achados, sem erros ou avisos. Para os testes
CPU, o executável Ollama e o modelo já instalados foram fornecidos externamente
ao pacote, conforme os pré-requisitos do README.

## Problemas encontrados e resolvidos

- A expansão de referências protegidas fez o DVWA alcançar o limite antigo de
  300 requisições antes dos extras. O padrão passou a 600; no `low` bastaram 390.
- O teto de 12 chamadas ao Ollama não mudou as prioridades após o primeiro login
  no DVWA. O novo teto padrão é 4, com uma chamada reservada para login tardio;
  a execução usou 3 chamadas e registrou 1819 tokens, contra 12 e 8067 antes.
- O formulário do Mutillidae tinha botão Login e texto “register here”. A
  classificação passou a priorizar o botão de envio; o login foi tentado, sem
  reivindicar autenticação verificada sem recurso protegido estável.
- Um cookie de um caractere corrompia dígitos de `127.0.0.1` na redação final.
  A origem das URLs agora é preservada; regressão e Mutillidae real confirmaram.
- O Juice Shop ultrapassou 1 MiB por resposta em `main.js`. Com 2 MiB apenas
  nesse teste, a leitura foi completa; a falta de rotas HTML continuou explícita
  como cobertura parcial.
- O diagnóstico HEAD foi retirado: status e headers não comprovavam acesso ao
  conteúdo protegido. A confirmação obrigatória continua em GET→POST reproduzido.

## Como reproduzir

Na pasta do scanner, com Ollama e `qwen2.5:3b` instalados localmente:

```sh
./test.sh --live --cpu
```

O comando instala dependências locais, verifica inferência real e roda os dois
cenários controlados. Para o DVWA separado e iniciado na porta 4280:

```sh
BASE_URL=http://127.0.0.1:4280 CHALLENGE_USERNAME=admin CHALLENGE_PASSWORD=password ./run.sh --cpu
```

Trocar o nível no navegador não altera a sessão nova criada pelo scanner. Veja
`docs/teste-dvwa.md` para ajustar `DEFAULT_SECURITY_LEVEL` no container.

Juice Shop foi usado localmente em `127.0.0.1:4281` ([projeto OWASP](https://owasp.org/projects/juice-shop/));
Mutillidae II em `127.0.0.1:4282` ([repositório oficial](https://github.com/webpwnized/mutillidae-docker)).
São laboratórios independentes e não integram a entrega. O Mutillidae exigiu
compatibilidade x86-64 no Mac Apple Silicon.

## Limites de interpretação

`completed` significa que o fluxo terminou dentro dos limites, não que o alvo
esteja seguro. `partial` preserva achados, mas indica cobertura incompleta.
Resultados negativos valem somente para o recurso e a condição analisados.
As verificações de CPF e GET→POST têm casos positivos com IA real nas fixtures;
DVWA, Juice Shop e Mutillidae não forneceram casos positivos observados desses
dois tipos. Não há alegação de taxa universal de falsos positivos ou de cobertura
do OWASP Top 10. JavaScript dinâmico, MFA/SSO, páginas mutáveis e verbos perigosos
permanecem fora do escopo implementado. Veja `docs/interpretacao-resultados.md`.

O ZIP final foi gerado após esses testes, inspecionado quanto a integridade,
permissões executáveis e ausência de arquivos de trabalho e credenciais. O pacote
não foi publicado nem enviado automaticamente.
