# Heavily based off https://sohlich.github.io/post/go_makefile/
# pared down from the above and added deps download via go mod

# Go parameters
GOCMD=~/.go/bin/go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GETDEPS=$(GOCMD) mod download
BINARY_NAME=readBro.out

all: deps test build
build:
		$(GOBUILD) -o $(BINARY_NAME) -v
		@echo "build done run with: ./$(BINARY_NAME)"
test:
		$(GOTEST) -v ./...
tests: test
clean:
		$(GOCLEAN)
		rm -f $(BINARY_NAME)
run:
		$(GOBUILD) -o $(BINARY_NAME) -v
		./$(BINARY_NAME)
deps:
		$(GOGETGETDEPS)
