# Teste independente com DVWA

O DVWA roda separado do scanner. O scanner acessa sua URL por HTTP; não precisa
ler seu código nem compartilhar diretórios com ele. A validação compara o nível
`impossible` com `low`, sem presumir que cada módulo corresponda a um detector.
SQL injection e XSS não estão implementados neste scanner.

## Atenção à sessão usada no teste

A seleção em **DVWA Security** altera o cookie do navegador. O scanner inicia
outra sessão; para testar seu login automático no nível desejado, configure
`DEFAULT_SECURITY_LEVEL` no serviço DVWA e recrie o serviço. Não basta mudar o
nível na interface do navegador.

Exemplo de arquivo Compose adicional, salvo fora do código do scanner:

```yaml
services:
  dvwa:
    environment:
      DEFAULT_SECURITY_LEVEL: low
```

Aplique usando o Compose original como primeiro arquivo e o adicional como
segundo, com caminhos absolutos:

```sh
docker compose -f /caminho/DVWA/compose.yml -f /caminho/dvwa-low.compose.yml up -d --pull never dvwa
```

Mantenha a publicação original em `127.0.0.1:4280:80`. Após inicializar o banco
pela interface do DVWA, execute na pasta do scanner:

```sh
BASE_URL=http://127.0.0.1:4280 CHALLENGE_USERNAME=admin CHALLENGE_PASSWORD=password ./run.sh --cpu
```

As credenciais acima são as credenciais de laboratório do DVWA. Cada execução
sobrescreve `findings.json`; preserve o relatório anterior antes da comparação.
Para voltar ao cenário protegido, troque `low` por `impossible` no arquivo
adicional e aplique novamente o mesmo comando Compose.

Os resultados medidos estão em `docs/validacao.md`. Um resultado negativo só
se aplica à condição e aos recursos efetivamente testados. Testes inconclusivos
não devem ser apresentados como evidência de proteção.
