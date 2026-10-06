> Nota: este documento registra uma etapa didática anterior. Para o comportamento atual, consulte README.md e docs/guia-tecnico.md.

# Cliente HTTP: lógica e sintaxe da primeira implementação

Este registro explica as mudanças de 30/09/2026. O programa realiza uma requisição
e lê o corpo com limite. Ainda não faz crawling nem detecta vulnerabilidades.

## 1. Constantes: limites em um único lugar

`MAX_BODY_BYTES = 1024 * 1024` define 1.048.576 bytes (1 MiB).
`CHUNK_SIZE = 8192` define blocos de 8 KiB.

`*` multiplica. Letras maiúsculas são uma convenção para indicar constantes;
Python não impede que o valor seja alterado. Centralizar os valores evita números
repetidos pelo código. A configuração por ambiente será conectada posteriormente.

## 2. Uma função com entradas e resultados explícitos

```python
def read_limited_body(
    response: httpx.Response, limit: int = MAX_BODY_BYTES
) -> Tuple[bytes, bool]:
```

- `def` define uma função: um bloco de código chamado pelo nome.
- `response` é a resposta HTTP que a função recebe.
- `limit` é a quantidade máxima de bytes a armazenar; o valor após `=` é o padrão
  quando o chamador não informa outro limite.
- `: httpx.Response` e `: int` são anotações de tipo. Documentam os valores
  esperados e ajudam ferramentas; não validam os tipos automaticamente.
- `-> Tuple[bytes, bool]` indica que a função retorna dois valores: bytes e um
  booleano (`True` ou `False`). `Tuple` vem de `typing`, compatível com Python 3.9.
- O texto entre três aspas é uma docstring, a documentação da função.
- `if limit <= 0` rejeita um limite sem sentido. `raise ValueError(...)` sinaliza
  ao chamador que esse argumento é inválido.

## 3. Compressão: negociação e verificação

O cliente envia `Accept-Encoding: identity`, solicitando que o conteúdo não seja
comprimido. O dicionário `{"Accept-Encoding": "identity"}` associa nome e valor
do header. Isso é um pedido; o servidor pode ignorá-lo.

Por isso examinamos `Content-Encoding` na resposta. `.get(..., "")` obtém o
header ou uma string vazia se estiver ausente; `.strip()` remove espaços nas
extremidades e `.lower()` normaliza as letras para minúsculas.

`encoding not in ("", "identity")` significa: se o valor não for nenhum dos dois
permitidos. Nessa situação levantamos `UnsupportedContentEncoding` antes de ler
o corpo. Essa classe herda de `Exception`, criando um tipo específico de erro.

Escolhemos rejeitar compressão nesta leitura para não descompactar sem um limite
de saída. Alternativas seriam confiar na descompressão automática ou implementar
um descompressor incremental com limites. A primeira enfraquece o controle de
recursos; a segunda exige implementação e testes adicionais. O comportamento
atual é explícito e reduz cobertura em servidores que insistam em comprimir.

## 4. Acumular bytes com limite

`body = bytearray()` cria uma sequência de bytes que pode crescer.
`truncated = False` começa indicando que não observamos conteúdo excedente.

```python
for chunk in response.iter_raw(chunk_size=CHUNK_SIZE):
    remaining = limit - len(body)
    body.extend(chunk[:remaining])
```

- `for` repete o bloco para cada pedaço fornecido pelo HTTPX.
- `iter_raw` entrega bytes sem descompressão de conteúdo automática. O HTTPX
  ainda trata o enquadramento HTTP; não estamos lendo pacotes TCP diretamente.
- `chunk_size` controla os blocos entregues à nossa função, não pacotes da rede.
- `len(body)` conta os bytes já guardados.
- `remaining` calcula o espaço restante.
- `chunk[:remaining]` é um slice: pega do começo do bloco até a quantidade
  permitida, sem incluir a posição final.
- `.extend(...)` acrescenta esses bytes ao acumulador.

Exemplo: limite de 10 bytes, com 8 guardados, e chegada de mais 5. Restam 2;
guardamos somente os primeiros 2 do bloco e identificamos que outros 3 ficaram
fora do limite.

`if len(chunk) > remaining` detecta essa sobra; `truncated = True` registra o
resultado e `break` encerra a repetição. Se o corpo tiver exatamente o limite,
não chamamos isso de truncamento sem observar bytes adicionais.

O limite se aplica ao corpo armazenado, não a toda a memória do processo. Há
buffers do transporte, um bloco em processamento e uma cópia ao converter para
`bytes`. Não prometemos que o processo inteiro usará apenas 1 MiB de RAM.

## 5. Devolver e receber os resultados

`return bytes(body), truncated` converte o acumulador em bytes imutáveis e devolve
uma tupla com o conteúdo e o indicador. Imutável significa que seus bytes não
podem ser alterados no mesmo objeto depois da conversão.

No chamador, `body, truncated = read_limited_body(response)` desempacota a tupla:
o primeiro resultado vai para `body`, o segundo para `truncated`.

Os prints usam f-strings (`f"...{expressão}..."`) para inserir valores no texto.
Mostramos status, tamanho e truncamento, não o corpo, que pode conter informações
sensíveis. Um status de erro, como 404 ou 500, também tem seu corpo lido.

## 6. Organização da execução e tratamento de falhas

O código anterior de configuração foi colocado em `def main() -> int`. Isso
permite chamar o fluxo nos testes sem executar o programa no momento da importação.
A validação anterior de esquema, host, porta e credenciais foi preservada.

```python
if __name__ == "__main__":
    raise SystemExit(main())
```

Quando o arquivo é executado diretamente, Python define `__name__` como
`"__main__"`; quando ele é importado, esse valor é o nome do módulo. Esse teste
faz a execução automática ocorrer apenas no primeiro caso.

`return 0` indica sucesso. `SystemExit(main())` usa esse resultado como código
de saída do processo. Um `SystemExit` com mensagem de texto encerra com erro e
mostra a mensagem.

`try` contém operações que podem falhar; `except` trata tipos específicos de
falha. `except ... as error` guarda o erro na variável `error`; `str(error)`
obtém sua mensagem. Essa mensagem é nossa, fixa, para o caso de compressão.
Erros do HTTPX usam mensagens genéricas sem reproduzir URLs ou dados internos.
`from None` suprime o encadeamento de exceções ao apresentar a falha.

Os dois blocos `with` fecham a resposta e o cliente ao terminar, inclusive após
`break` ou exceção. Timeout de leitura limita a espera por um bloco de dados;
não é um limite total de duração da execução.

## 7. Testes: o que foi acrescentado e por quê

Arquivo: `tests/test_main.py`. O pytest encontra funções que começam com `test_`.
`assert` verifica condições; uma condição falsa faz o teste falhar.

`TrackedStream` herda de `httpx.SyncByteStream` e fornece blocos em memória.
`__init__` inicializa o objeto, `self` representa aquela instância, `__iter__`
fornece seus blocos e `yield` entrega um bloco por vez. Contamos blocos lidos e
registramos o fechamento para verificar que o leitor realmente para.

`@pytest.mark.parametrize` executa o mesmo teste com conjuntos diferentes de
entradas. Os casos verificam corpo vazio, abaixo do limite, exatamente no limite
e acima dele, incluindo a fronteira entre dois blocos. São importantes para
evitar um resultado incorreto apenas nos limites de tamanho.

`b"abc"` é um literal de bytes. `b"x" * 8192` repete um byte para gerar dados de
teste. Uma lista multiplicada repete os elementos usados pelo stream de teste.

`with pytest.raises(...)` exige que o código dentro do bloco produza a exceção
esperada. `try/finally` garante fechamento do objeto mesmo se uma asserção falhar.

`httpx.MockTransport` fornece respostas controladas sem sockets. `monkeypatch`
substitui temporariamente a criação do cliente e as variáveis de ambiente,
restaurando-as após o teste. O helper `mock_client` preserva o cliente real e
injeta somente o transporte de testes. `**options` captura/repassa os argumentos
nomeados do cliente. Isso também permite verificar timeouts e flags de segurança.

`capsys` captura a saída para conferirmos as mensagens e a ausência do conteúdo
sensível. `lambda request: ...` é uma função curta usada por um desses testes
para devolver uma resposta sem criar outra função nomeada.

Além dos limites, os testes cobrem compressão rejeitada antes da leitura,
Content-Length que não substitui a contagem de bytes, status 200/404/500,
redirecionamento externo não seguido, erros de rede e alvos inválidos rejeitados
antes da criação do cliente. Eles não provam segurança absoluta ou precisão de
detectores ainda não implementados.

## 8. Dependências e execução

`requirements.txt` declara `httpx==0.28.1`; `==` fixa a versão dessa dependência.
`requirements-dev.txt` inclui o primeiro arquivo com `-r requirements.txt` e
declara `pytest==8.4.2`. O pytest foi instalado apenas na `.venv` do projeto.
As versões das dependências transitivas ainda serão fechadas no empacotamento.

```sh
BASE_URL=http://127.0.0.1:3000 .venv/bin/python main.py
.venv/bin/python -m pytest -q
```

`-m pytest` executa o pytest com o mesmo Python do projeto; `-q` reduz a saída.
Resultado verificado: 33 testes passaram. A chamada real ao servidor local
retornou status 200, 219 bytes e `Conteúdo truncado: False`.
