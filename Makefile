.PHONY: default fmt test lint

define run
	@fail=0; \
		printf '➡️  make %-12s ' "$(1) ..."; \
		if out=$$($(MAKE) $(1) 2>&1); then \
			echo "✅"; \
		else \
			echo "❌"; \
			printf '%s\n' "$$out" | sed 's/^/    /'; \
			fail=1; \
		fi; \
	exit $$fail
endef

default:
	$(call run,lint)
	$(call run,test)

fmt:
	golangci-lint fmt

test:
	go test -race ./...

lint:
	golangci-lint run
