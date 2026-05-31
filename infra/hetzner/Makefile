TF := $(shell command -v tofu 2>/dev/null || command -v terraform 2>/dev/null)

ifndef TF
$(error Neither tofu nor terraform found on PATH)
endif

.PHONY: init plan deploy destroy kubeconfig

init: ## Initialize OpenTofu/Terraform
	$(TF) init

plan: ## Preview changes
	$(TF) plan

deploy: init ## Deploy the server (single command)
	$(TF) apply -auto-approve
	@echo ""
	@echo "Server deployed. Fetch kubeconfig:"
	@$(TF) output -raw kubeconfig_command

destroy: ## Destroy the server
	$(TF) destroy

kubeconfig: ## Fetch kubeconfig from the server
	@eval "$$($(TF) output -raw kubeconfig_command)"
	@echo "Kubeconfig saved to ./kubeconfig.yaml"
	@echo "Export it: export KUBECONFIG=$$(pwd)/kubeconfig.yaml"
