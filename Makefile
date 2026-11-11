IMG ?= yas-suricata-operator:dev
.PHONY: test build image manifests

test:
	go test ./...
build:
	go build -o bin/manager ./cmd/manager
image:
	docker build -t $(IMG) .
manifests:
	kubectl kustomize config
