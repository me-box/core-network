IMAGE_NAME=core-network
DEFAULT_REG=databoxsystems
VERSION=latest

.PHONY: all
all: build-amd64 build-arm64v8 publish-images

.PHONY: build-amd64
build-amd64:
	docker build -t $(DEFAULT_REG)/$(IMAGE_NAME)-amd64:$(VERSION) . $(OPTS)
	docker build -t $(DEFAULT_REG)/$(IMAGE_NAME)-relay-amd64:$(VERSION) -f Dockerfile-relay . $(OPTS)

.PHONY: build-arm64v8
build-arm64v8:
	docker build -t $(DEFAULT_REG)/$(IMAGE_NAME)-arm64v8:$(VERSION) -f Dockerfile-arm64v8 .  $(OPTS)
	docker build -t $(DEFAULT_REG)/$(IMAGE_NAME)-relay-arm64v8:$(VERSION) -f Dockerfile-relay . $(OPTS)

.PHONY: publish-images
publish-images:
	docker push $(DEFAULT_REG)/$(IMAGE_NAME)-amd64:$(VERSION)
	docker push $(DEFAULT_REG)/$(IMAGE_NAME)relay-amd64:$(VERSION)
	docker push $(DEFAULT_REG)/$(IMAGE_NAME)-arm64v8:$(VERSION)
	docker push $(DEFAULT_REG)/$(IMAGE_NAME)relay-arm64v8:$(VERSION)

.PHONY: test
test:
#NOT IMPLIMENTED