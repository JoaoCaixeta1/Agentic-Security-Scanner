> Nota: este documento registra uma etapa didática anterior. Para o comportamento atual, consulte README.md e docs/guia-tecnico.md.

# Da página recebida aos links descobertos

## O problema concreto

O scanner recebe apenas um endereço inicial. Não pode pressupor que existam
`/produtos`, `/login` ou qualquer outra rota. Precisa encontrar pistas na aplicação.
Uma dessas pistas é um link em uma página HTML.

HTML é um texto com marcações que descrevem a estrutura de uma página. Por
exemplo, `<a href="/produtos">Produtos</a>` define um link: `a` é a tag,
`href` é um atributo com o destino, e `Produtos` é o texto visível.

Esses nomes de rotas são apenas exemplos didáticos. Não foram incluídos como
alvos pré-programados no scanner.

## O percurso completo dos dados

1. O scanner pede a página inicial por HTTP.
2. O servidor devolve uma resposta: status, headers e corpo.
3. Nosso leitor guarda até 1 MiB do corpo. Um byte é uma unidade de dados;
   1 MiB equivale a 1.048.576 bytes. Em UTF-8, uma letra ASCII como `A` ocupa um
   byte; caracteres como `á` ocupam mais de um. Tamanho em bytes não é número
   de linhas, caracteres ou páginas.
4. Se o header `Content-Type` declarar HTML, passamos o corpo ao parser.
5. O parser identifica links, e o scanner transforma seus destinos em URLs completas.
6. Os filtros removem destinos fora do alvo, credenciais e repetições.
7. Guardamos uma lista de candidatos a visita. Esta etapa não faz essas visitas.

Na chamada real verificada, o servidor devolveu 219 bytes de HTML, sem links.
Isso explica a contagem zero; não é uma falha de descoberta.

## Exemplo acompanhado

Página recebida de `http://127.0.0.1:3000/`:

```html
<a href="/produtos">Produtos</a>
<a href="/produtos#topo">Voltar ao topo</a>
<a href="https://externo.invalid/">Outro site</a>
```

O primeiro destino está incompleto: não informa protocolo nem host. Como começa
com `/`, aponta para um caminho na raiz do site. Completado, fica
`http://127.0.0.1:3000/produtos`.

O segundo aponta para a mesma página, mas com um fragmento (`#topo`). Fragmentos
são instruções para a navegação no documento e não são enviados ao servidor no
pedido HTTP. Removê-los evita visitar repetidamente a mesma URL.

O terceiro usa outro host e protocolo. É descartado pela política de escopo.

Resultado do exemplo, testado em memória:

```text
http://127.0.0.1:3000/produtos
```

Já `/produtos?id=1` e `/produtos?id=2` permanecem separados: a query após `?`
é enviada ao servidor e pode mudar o conteúdo retornado.

## Ferramenta escolhida

Beautiful Soup permite procurar elementos dentro da estrutura do HTML. A biblioteca
foi aprovada no desenho e agora está instalada na `.venv` e fixada em
`requirements.txt`. Usamos o parser `html.parser`, que já acompanha Python.

Uma regex poderia procurar um padrão textual, mas ficaria mais frágil diante de
aspas diferentes, atributos fora de ordem e marcação imperfeita. Um navegador
executaria JavaScript e cobriria mais aplicações, com maior consumo e instalação
mais complexa; está fora do escopo aprovado. Este parser não executa scripts.

## Como ler as principais linhas de discovery.py

```python
soup = BeautifulSoup(body, "html.parser")
```

`body` contém os bytes recebidos. Essa chamada constrói uma representação do HTML
que o programa consegue consultar. `soup` é só o nome dado a essa representação.
Não é um servidor nem uma requisição.

```python
for tag in soup.find_all(["a", "area"], href=True):
    reference = tag["href"].strip()
```

`find_all` procura elementos `a` e `area` que tenham o atributo `href`. `area`
também pode representar um link, associado a uma região de imagem. A lista entre
colchetes contém os nomes das tags procuradas. `for` processa cada elemento;
`tag["href"]` lê o atributo e `.strip()` remove espaços nas extremidades.

Se o destino estiver vazio ou começar com `#`, `continue` pula para o próximo
elemento. `continue` pula uma iteração; `break` encerraria toda a repetição.

```python
candidate = base.join(reference).copy_with(fragment=None)
```

`base` é uma URL interpretada por HTTPX, não apenas texto. `.join()` completa
referências relativas; `.copy_with(fragment=None)` cria uma cópia sem fragmento.
Uma referência completa já informa seu próprio destino, que ainda será validado.

```python
origin = (page.scheme, page.host, page.port)
```

Os parênteses agrupam três valores em uma tupla. Eles identificam a origem da
página: esquema, host e porta. Para cada candidato comparamos os mesmos três
campos; `!=` significa diferente. Qualquer diferença faz o candidato ser descartado.

Mesmo `localhost` e `127.0.0.1` são tratados como hosts diferentes nesta regra,
embora normalmente alcancem o mesmo computador. A política é mesma origem,
não apenas mesma máquina. Portas padrão explícitas são normalizadas pelo HTTPX:
HTTP sem porta e HTTP na porta 80 são equivalentes.

```python
seen = set()
links = []
```

`set` cria um conjunto, útil para verificar rapidamente se uma URL já apareceu.
`links` é uma lista que preserva a ordem de descoberta. `seen.add(url)` registra
a URL no conjunto; `links.append(url)` a acrescenta ao final da lista.

Se uma nova URL única exceder o limite de 100 links, devolvemos o que já foi
coletado e registramos `limit_reached=True`. Repetições não consomem esse limite.

## O endereço base do HTML

Uma página pode conter `<base href="/catalogo/">`. Nesse caso, um link relativo
como `detalhes` deve ser completado como `/catalogo/detalhes`. Essa regra é parte
do HTML, não uma instrução para ampliar o alvo autorizado.

Por isso a base usada para completar links pode mudar, mas a origem permitida
continua sendo a da página recebida. Uma base externa não libera acesso externo.
Uma base malformada gera um motivo explícito para pular a descoberta. Usamos
`urlsplit` para conferir estrutura e porta, pois o parser do HTTPX tolerou um
endereço malformado detectado por um teste.

## Resultado agrupado e tipos novos

`@dataclass` pede ao Python que crie a inicialização de uma classe de dados.
`LinkDiscovery` funciona como uma ficha com três campos: `links`,
`limit_reached` e `skipped_reason`. Assim não confundimos uma página sem links
com uma resposta que nem pôde ser analisada como HTML.

`List[str]` indica lista de textos. `Optional[str]` indica um texto ou `None`;
`None` representa ausência de valor. Anotações descrevem os tipos esperados,
mas não substituem validação dos dados. Os valores após `=` são padrões.

`-> LinkDiscovery` informa o tipo de resultado da função. `return` devolve esse
resultado e encerra a função. `LinkDiscovery(links, limit_reached=True)` cria
uma ficha cujo campo de limite está marcado.

## Tipo de conteúdo e ligação com main.py

`Content-Type` descreve o formato do corpo. Exemplos: `text/html` para HTML e
`application/json` para JSON. Esse header é diferente de `Content-Encoding`,
que usamos antes para detectar compressão.

`.split(";", 1)[0]` pega a parte anterior ao primeiro ponto e vírgula. Assim,
`text/html; charset=utf-8` é reconhecido como HTML. `strip` e `lower` normalizam
espaços e maiúsculas. Tipo ausente ou diferente não é adivinhado: registramos que
a descoberta foi ignorada. Isso é uma limitação quando o servidor informa o tipo
incorretamente, e não prova ausência de links.

No `main.py`, `from discovery import extract_links` importa a função do novo
arquivo. Depois de ler o corpo, passamos três entradas: bytes, URL da resposta
e tipo de conteúdo. `str(response.url)` converte o objeto URL em texto.
O resultado permite imprimir as contagens e os motivos sem mostrar URLs que
possam conter informações sensíveis na query.

## Testes acrescentados

Os testes verificam resolução de links relativos, preservação de queries,
remoção de duplicatas, limites, HTML incompleto, tipos de conteúdo e bases HTML.
Os casos de escopo incluem mudança de protocolo, host, porta e credenciais.

O teste integrado entrega HTML controlado ao `main` e verifica a contagem de
links. Também exige que tenha ocorrido somente uma requisição: encontrar um link
ainda não autoriza visitá-lo nesta etapa.

Resultado: 62 testes passaram, incluindo os 33 anteriores. Nenhum dos testes
precisa acessar alvos externos.

Referência: [Documentação do Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/).
