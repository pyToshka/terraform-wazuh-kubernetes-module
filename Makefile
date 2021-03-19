MODULES = $(sort $(dir $(wildcard ./)))

.PHONY: docs $(MODULES)
docs: $(MODULES)

$(MODULES):
	terraform-docs markdown $@ > $@README.md
