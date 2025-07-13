# API de Assinatura Digital

Esta aplicação é uma API para geração e verificação de assinaturas digitais em arquivos, utilizando o padrão CMS (Cryptographic Message Syntax) e certificados digitais no formato PKCS#12.

**Atenção:** Esta API tem fins **exclusivamente educacionais**. A definição de variáveis sensíveis diretamente no `docker-compose.yml`, como senha de certificados, **não é recomendada em ambientes de produção**. 
Existem inúmeras formas de manipular essas envs de forma segura.

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

### 1. Clonar o repositório
```bash
git clone https://github.com/vilelacode/document-signing-api.git
cd api
```

### 2. Executar com Docker Compose
```bash
docker compose up --build
```
A aplicação estará disponível em `http://localhost:8080`.

> As variáveis de ambiente necessárias (como `ALIAS` e `PASSWORD`) já estão definidas no `docker-compose.yml`.

## Estrutura de Pastas Importantes
- `src/main/resources/arquivos/` — Exemplo de arquivos para assinar
- `src/main/resources/cadeia/` — Certificados confiáveis
- `src/main/resources/pkcs12/` — Certificados PKCS#12 para assinatura
- `signed-files/` — Onde as assinaturas geradas são salvas

## Observações
- Os endpoints aceitam arquivos via multipart/form-data.
- Certifique-se de fornecer arquivos e senhas corretos para o funcionamento adequado.

---

Para dúvidas ou sugestões, entre em contato! 
