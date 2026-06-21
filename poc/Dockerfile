# Dockerfile (na pasta poc/)
FROM golang:1.24-alpine

RUN apk add --no-cache git

WORKDIR /app

# Copia todo o mono repo
COPY . .

# Ajusta para a pasta do módulo principal
WORKDIR /app/poc

# Baixa dependências (go.mod + go.sum já estão na pasta)
RUN go mod download

# Para PoC, roda direto
CMD ["go", "run", "main.go"]
