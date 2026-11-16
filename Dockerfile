FROM golang:1.27.4 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gordian ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot AS prod

WORKDIR /app

ENV APP_TEMPLATES_DIR=/app/internal/templates

COPY --from=builder /out/gordian /app/gordian
COPY --from=builder /src/internal/templates /app/internal/templates

EXPOSE 10000

USER nonroot:nonroot

ENTRYPOINT ["/app/gordian"]
