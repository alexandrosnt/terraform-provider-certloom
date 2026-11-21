TFPLUGINDOCS = github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0

build:
	go build ./...

test:
	go test ./...

# Needs a server: CERTLOOM_SRC=../certloom scripts/testserver.sh start && . .testserver/env
testacc:
	TF_ACC=1 TF_ACC_PROVIDER_NAMESPACE=alexandrosnt go test -count=1 -timeout 30m ./...

lint:
	golangci-lint run

docs:
	go run $(TFPLUGINDOCS) generate --provider-name certloom

.PHONY: build test testacc lint docs
