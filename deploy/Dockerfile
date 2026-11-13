FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/authz ./cmd/authz

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/authz /authz
USER nonroot:nonroot
ENTRYPOINT ["/authz"]
CMD ["serve"]