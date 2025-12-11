FROM golang:1.25.5 AS builder

WORKDIR /gordian-build

RUN apt-get update && \
    apt-get install -y --no-install-recommends make ca-certificates && \
    update-ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make build

FROM scratch

WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /gordian-build/main /app/
COPY --from=builder /gordian-build/internal/templates /app/internal/templates

EXPOSE 8080

ENTRYPOINT ["/app/main"]
