NAME := moss
DIST_DIR := dist
TARGET ?= $(shell rustc -vV | awk '/host:/ { print $$2 }')
ARCHIVE := $(DIST_DIR)/$(NAME)-$(TARGET).tar.gz

.PHONY: build changelog ci clean clippy dist fmt test

build:
	cargo build --workspace --locked

fmt:
	cargo fmt -- --check

clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --locked

ci: fmt clippy test

dist:
	cargo build --workspace --release --locked --target $(TARGET)
	mkdir -p $(DIST_DIR)
	tar -czf $(ARCHIVE) -C target/$(TARGET)/release $(NAME)

clean:
	rm -rf target $(DIST_DIR)

changelog:
	@if test -n "$$(git status --porcelain)"; then \
		echo "working tree is not clean"; \
		git status --short; \
		exit 1; \
	fi
	@set -e; \
	version="$$(git-cliff --bumped-version)"; \
	echo "Generating CHANGELOG.md for $$version"; \
	git-cliff --tag "$$version" -o CHANGELOG.md; \
	git add CHANGELOG.md; \
	git commit -m "chore(release): prepare for $$version"
