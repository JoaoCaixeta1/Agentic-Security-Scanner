# Guia para entender e defender a implementação

Este é o roteiro para estudarmos depois da entrega, acompanhando os arquivos no VS
Code. Não é preciso decorar nomes; o objetivo é explicar comportamento e escolhas.

## 1. Entrada, origem e rede

`Settings.from_env()` transforma texto do ambiente em configuração validada.
`@dataclass` cria a estrutura de dados com campos e valores padrão. `@classmethod`
permite construir a configuração pela classe, sem uma instância anterior.

Exemplo: em `http://127.0.0.1:3000/conta`, HTTP é o protocolo, 127.0.0.1 é o endereço
do próprio computador, 3000 identifica a porta do serviço e `/conta` é o caminho.
`Scope.require()` compara a tupla `(scheme, host, port)`: mudar só o caminho pode;
mudar para porta 11434 não pode. Essa porta pode ser de outro serviço, como Ollama.

`raise ScopeError(...)` interrompe a operação antes de abrir a conexão. Não é uma
resposta HTTP do servidor: é uma decisão do scanner. Um HTTP 403, por outro lado,
prova que houve resposta HTTP; um timeout não prova isso.

**Defesa na entrevista:** validar apenas BASE_URL não basta, porque o alvo controla
links, forms e redirects. A mesma política precisa proteger cada requisição.
Loopback vale para a máquina que executa o scanner, inclusive a do avaliador.

## 2. Streaming e orçamento

`with client.stream(...) as response:` abre a resposta e garante fechamento ao sair
do bloco, inclusive por erro. `for chunk in response.iter_raw()` recebe pedaços de
bytes. O código guarda no máximo 1 MiB por corpo: 1.048.576 bytes.

“Resposta” é o que o servidor devolveu a **uma** requisição: status, cabeçalhos e
corpo. Aqui, o limite de armazenamento vale para o corpo, não para a aplicação inteira.
O orçamento agregado é separado, assim como o limite de requisições.

`remaining = limit - len(body)` calcula quanto ainda cabe. `chunk[:remaining]` pega
só essa parte. `truncated=True` informa que a análise não viu tudo. O cabeçalho
`Content-Length` não substitui contar os bytes realmente recebidos.

`time.monotonic()` mede duração sem depender de ajustes no relógio civil. Timeout
de leitura limita a espera por dados; o prazo total também impede que um servidor
mantenha o scan vivo enviando dados muito lentamente.

**Alternativa:** carregar `response.content` por completo é simples, mas pode
consumir memória descontroladamente. Aceitar gzip exigiria limitar também os bytes
descomprimidos; esta versão pede identity e registra falha se vier comprimido.

## 3. Descoberta e autenticação

A fila `deque` guarda URL e profundidade. `popleft()` retira o próximo recurso.
Um `set` evita repetir a mesma URL na mesma fase de autenticação. A mesma página
pode precisar de nova visita depois do login porque passa a mostrar outros links.

Beautiful Soup transforma HTML em elementos: links, forms e inputs. O scanner
preserva campos ocultos, incluindo um eventual CSRF. Não tenta `/login` por palpite:
usamos a ação encontrada no documento. O login JSON só é aceito quando há uma
referência literal reconhecível no script; não executamos JavaScript.

Uma sessão é estado mantido entre requisições, geralmente por cookie ou token.
`fork()` cria um cliente separado: comparar esse cliente sem sessão com o cliente
autenticado é o controle que permite discutir autorização.

**Por que não basta 200?** Uma senha errada pode devolver uma página de login com
status 200. Por isso verificamos acesso a conteúdo protegido e estável, diferente
do conteúdo obtido pelo cliente anônimo.

## 4. O que a IA faz

Ollama recebe uma lista pequena de recursos com IDs e campos sem valores. O modelo
propõe a ordem da exploração e a correspondência dos campos de login. Pydantic
valida os tipos e rejeita campos extras; depois o código verifica se cada ID
realmente existe entre os apresentados.

`Optional[str]` aceita uma string ou `None`. `List[str]` descreve uma lista de
strings. `model_validate_json()` transforma JSON em um objeto validado ou gera
uma exceção. O `try/except` trata essa falha sem executar o plano rejeitado.

**Prompt injection:** uma página pode conter “ignore suas regras”. Ela é dado do
alvo, não instrução nossa. Mesmo se o modelo obedecer, só consegue devolver opções
que passam pelo schema, pela lista de IDs e pela política do gateway. Ele não ganha
shell, novas URLs ou poder de declarar achados.

**Alternativa:** deixar o modelo gerar qualquer requisição amplia flexibilidade,
mas dificulta limitar efeitos e reproduzir conclusões. As decisões restritas são
mais fáceis de auditar. O risco residual inclui uma priorização ruim de opções válidas.

## 5. Evidência e falsos positivos

CPF usa aritmética dos dois dígitos verificadores e contexto do campo. Uma sequência
com checksum correto não prova que é de uma pessoa real. O relatório afirma a
exposição observada e deixa a interpretação de autorização explícita.

No method tampering, imagine:

1. GET com sessão retorna o registro protegido.
2. GET sem sessão retorna 403.
3. POST sem sessão retorna exatamente o registro protegido, duas vezes.
4. Novo GET sem sessão continua retornando 403.

Essa comparação sustenta a falha. Um POST 200 com a palavra “OK” não satisfaz o
teste. `same_content()` compara conteúdo e tipo completos; páginas dinâmicas podem
ficar inconclusivas. É uma escolha consciente de precisão contra cobertura.

Cookie: removemos um cookie por vez e comparamos com a sessão restaurada. Exigimos
ainda que o cookie sozinho dê acesso: isso evita confundir um cookie CSRF necessário
com a credencial de autenticação. Logout:
usamos uma cópia antiga do cookie **depois** de verificar que a sessão atual saiu.
Redirect: alteramos o destino de um parâmetro descoberto, mas lemos apenas Location;
a URL externa reservada `.invalid` nunca é acessada.

**Resposta defensável:** não existe promessa geral de zero falsos positivos. Temos
casos negativos, casos ambíguos, controles repetidos e métricas limitadas à suíte.
Também testamos que os casos vulneráveis são encontrados, evitando um scanner que
“não erra” porque nunca encontra nada.

## 6. Saída confiável

`Results.add()` deduplica por tipo, URL, método e discriminador. `Finding` define os
campos aceitos; a IA não constrói esse objeto. Dados sensíveis são mascarados.

`write_report()` escreve primeiro em um arquivo temporário e chama `os.replace()`.
Assim, o leitor vê a versão anterior ou a nova, sem um JSON escrito pela metade.
O `finally` em `main()` tenta finalizar o relatório mesmo após erro ou Ctrl+C.

`completed` descreve o fluxo concluído dentro da cobertura observada; `partial`
avisa sobre limites/falhas; `error` registra impedimento de execução. Encontrar zero
falhas é compatível com qualquer um desses estados e nunca significa “100% seguro”.

## Preparação para a conversa técnica

Comece explicando o contrato de execução e faça uma demonstração. Depois mostre
uma confirmação de bypass e um caso negativo. Só então abra os componentes.

As decisões mais importantes para defender são: limite de confiança da IA,
validação de cada destino, controle autenticado/anônimo, precisão versus cobertura,
ausência de navegador, execução sequencial e relatório de falhas explícito.




## Custo de IA e limite de cobertura

O teto de 4 chamadas ao Ollama é um compromisso: menos espera e tokens locais,
com chance menor de a IA repriorizar rotas descobertas tarde. Uma chamada fica
reservada para um formulário de login que apareça depois; o crawler continua em
ordem determinística quando não há nova escolha. No DVWA low, três chamadas
mantiveram a autenticação e os achados da execução com doze chamadas. A aplicação
Angular testada mostrou outro limite: baixar JavaScript não equivale a executar
seu código e descobrir rotas dinâmicas. O relatório sinaliza isso como parcial.
