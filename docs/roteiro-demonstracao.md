# Roteiro de demonstração e defesa

## Demonstração curta

1. Explique o escopo: scanner local recebe BASE_URL, descobre links/formulários,
   autentica quando reconhece o fluxo e entrega findings.json.
2. Mostre a divisão: Ollama prioriza IDs e campos descobertos; código restringe
   a execução e confirma as evidências. O modelo não decide vulnerabilidades.
3. Execute `./test.sh --live --cpu` com Ollama/modelo previamente instalados.
   A primeira etapa é determinística; as demais usam inferência real e dois
   servidores de teste, um vulnerável e outro protegido. Rotas são aleatórias.
4. Mostre os relatórios de referência em docs/exemplos e a validação registrada
   em docs/validacao.md. Diga de qual rodada é cada resultado.
5. Mostre o DVWA como validação independente: em impossible não houve achados;
   em low houve cookie sem HttpOnly e open redirect. São resultados registrados
   da versão atual, não uma medição universal de precisão.
6. Termine com os limites e melhorias futuras, sem afirmar que zero achados
   significa segurança nem que o projeto cobre todo o OWASP Top 10.

Para demonstrar um alvo iniciado pelo avaliador:

```sh
BASE_URL=http://localhost:3000 ./run.sh
```

As credenciais devem estar em CHALLENGE_USERNAME e CHALLENGE_PASSWORD quando
necessárias. Para o ambiente desta máquina, `./run.sh --cpu` usa Ollama temporário.
Confirme a URL e o serviço alvo; os servidores efêmeros dos testes já estarão
encerrados depois de test.sh terminar.

## Respostas técnicas que precisam estar claras

**Por que não basta status 200?** Pode ser página de login, erro com status errado
ou conteúdo público. No bypass GET→POST exigimos duas respostas com o conteúdo
protegido de referência e GET anônimo negado antes/depois.

**Por que não testar todos os métodos?** PUT/PATCH/DELETE podem alterar dados.
A confirmação atual é limitada a GET→POST; HEAD poderia adicionar diagnóstico, mas não
provaria acesso ao corpo. Ampliar métodos exige contratos/fixtures e critérios de
impacto, não apenas comparar status ou o header Allow.

**Por que código confirma e IA planeja?** O planejamento admite escolhas dentro
de um conjunto observado. A confirmação precisa ser reproduzível e auditável.
A validação de schema/IDs impede transformar saída arbitrária em uma ação nova.
Isso restringe o efeito de prompt injection; não demonstra imunidade absoluta.

**Por que comparação exata?** Reduz afirmações baseadas em semelhanças fracas.
Em contrapartida, páginas dinâmicas podem ficar inconclusivas e falhas reais
podem não ser detectadas. A limitação está explícita no README.

**CPF válido prova vazamento indevido?** Não. Checksum e contexto demonstram um
identificador plausível e completo na resposta. Pessoa real, necessidade de uso
e autorização exigem contexto de negócio. A confiança é média e o valor é omitido.

**O que acontece se a infraestrutura falha?** O relatório preserva o que já foi
coletado, registra o problema e diferencia parcial/erro de completed. Erro 5xx
na descoberta pode ocultar superfície e torna a cobertura parcial.

**Por que 3B em vez de 7B?** O enunciado permite outro modelo Ollama local. O 3B
foi validado nesta máquina; 7B apresentou instabilidade nas repetições. A escolha
prioriza execução reproduzível para uma tarefa de planejamento restrita.

**Qual a evidência contra falsos positivos?** Cenários protegidos, respostas
ambíguas e controles negativos não geraram achados nos testes registrados.
Isso não estima taxa universal de falsos positivos em aplicações desconhecidas.
