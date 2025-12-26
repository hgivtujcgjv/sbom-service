FROM docker-dev.registry-ci.delta.sbrf.ru/ci01544525/ci08120874/go:1.24.2 AS builder 

ARG SBEROSC_TOKEN

RUN go env -w GOPROXY="https://token:${SBEROSC_TOKEN}@sberosc.sigma.sbrf.ru/repo/go" \
    GOPRIVATE="stash.sigma.sbrf.ru" \
    GOSUMDB="sum.golang.org" 

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .


RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /sbom-serv ./cmd/api/main.go


FROM docker-dev.registry-ci.delta.sbrf.ru/ubi8-micro:8.9


WORKDIR /app

COPY /tools/syft /usr/local/bin/syft
COPY --from=builder /sbom-serv .
COPY docs/openapi.yaml /app/docs/
COPY certs /app/certs

EXPOSE 8082

CMD ["/app/sbom-serv"]
