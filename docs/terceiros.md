# Dependências de terceiros

`requirements-lock.txt` fixa as dependências Python de execução.
`requirements-dev.txt` acrescenta pytest para validação.

`vendor/` contém wheels obtidos do índice de pacotes Python, sem alterações. Os
arquivos `.dist-info` dentro de cada wheel preservam metadados e licenças dos
respectivos projetos. `vendor/SHA256SUMS` permite verificar a integridade dos
arquivos distribuídos e é verificado durante a instalação offline.

Ollama é um pré-requisito separado e não está redistribuído neste ZIP. O código,
os pesos dos modelos e suas licenças são disponibilizados por seus respectivos
projetos. Nenhum modelo ou cache de inferência é incluído no pacote de entrega.

O arquivo de checksums protege contra alteração acidental em relação ao manifesto;
não substitui a verificação da procedência de um pacote obtido de terceiro.
