# API de Assinatura Digital

Esta aplicação é uma API para geração e verificação de assinaturas digitais em arquivos, utilizando o padrão CMS (Cryptographic Message Syntax) e certificados digitais no formato PKCS#12.

## Tecnologias Utilizadas

- **Java 17**
- **Spring Boot 3**
- **Bouncy Castle** (biblioteca de criptografia)
- **Maven** (gerenciamento de dependências)
- **SLF4J/Logback** (logs)

## Endpoints Principais

- `POST /api/signature` — Gera uma assinatura digital para um arquivo enviado.
- `POST /api/verify` — Verifica a validade de uma assinatura digital enviada.

## Como Executar a Aplicação

### 1. Pré-requisitos
- Java 17 instalado
- Maven instalado

### 2. Clonar o repositório
```bash
git clone https://github.com/vilelacode/document-signing-api.git
cd api
```

### 3. Configurar as propriedades
Edite o arquivo `src/main/resources/application.properties` conforme necessário:
- `alias`: Alias do certificado no PKCS#12
- `app.signature.storage-dir`: Pasta onde as assinaturas serão salvas
- `certificates.directory`: Pasta com certificados de autoridades para validação

### 4. Executar a aplicação

#### Usando Maven:
```bash
mvn spring-boot:run
```

#### Ou gerando o JAR:
```bash
mvn clean package
java -jar target/api-0.0.1-SNAPSHOT.jar
```

A aplicação estará disponível em `http://localhost:8080`.

## Estrutura de Pastas Importante
- `src/main/resources/arquivos/` — Exemplo de arquivos para assinar
- `src/main/resources/cadeia/` — Certificados confiáveis
- `src/main/resources/pkcs12/` — Certificados PKCS#12 para assinatura
- `signed-files/` — Onde as assinaturas geradas são salvas

## Observações
- Os endpoints aceitam arquivos via multipart/form-data.
- Certifique-se de fornecer arquivos e senhas corretos para o funcionamento adequado.

---

Para dúvidas ou sugestões, entre em contato! 
