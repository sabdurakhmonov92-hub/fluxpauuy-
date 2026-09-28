# ==============================================================================
# FluxPay Infrastructure Automation Makefile (Task 67)
# The 2-command law: make check-syntax | make provision
# ==============================================================================

ANSIBLE_FLAGS ?=

.PHONY: help check-syntax provision

help:
	@echo "FluxPay Ansible Automation:"
	@echo "  make check-syntax             - Validate playbook syntax against example inventory"
	@echo "  make provision ANSIBLE_FLAGS= - Execute idempotent server provisioning"
	@echo ""
	@echo "Example execution:"
	@echo "  make provision ANSIBLE_FLAGS='--extra-vars \"doppler_token=dp.st.prod.XXXX\"'"

check-syntax:
	ansible-playbook -i inventory.example.yml playbook.yml --syntax-check $(ANSIBLE_FLAGS)

provision:
	ansible-playbook -i inventory.example.yml playbook.yml $(ANSIBLE_FLAGS)
