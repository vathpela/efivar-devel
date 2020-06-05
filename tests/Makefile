#
# Makefile
# Peter Jones, 2019-06-18 11:10
#

TESTS=test0 test1 test2 test3 test4 test5 test6 test7 test8 test9 test10 test11

all: clean $(TESTS)

GRUB_PREFIX ?= grub2
EFIVAR ?= $(TOPDIR)/src/efivar
EFISECDB ?= $(TOPDIR)/src/efisecdb

clean:
	@rm -f *.result.env *.result.var *.result.esl

test0:
	@echo testing export to DMPSTORE format
	@$(GRUB_PREFIX)-editenv test.0.result.env create
	@$(GRUB_PREFIX)-editenv test.0.result.env set debug=all,-scripting,-lexer
	@truncate -s 512 test.0.result.env
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n {grub}-GRUB_ENV -f test.0.result.env -D -e test.0.result.var
	@cmp test.0.result.var test.0.goal.var
	@rm test.0.result.*
	@echo passed

test1:
	@echo testing export to libefivar format
	@$(GRUB_PREFIX)-editenv test.1.result.env create
	@$(GRUB_PREFIX)-editenv test.1.result.env set debug=all,-scripting,-lexer
	@truncate -s 512 test.1.result.env
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n {grub}-GRUB_ENV -f test.1.result.env -e test.1.result.var
	@cmp test.1.result.var test.1.goal.var
	@rm test.1.result.*
	@echo passed

test2:
	@$(GRUB_PREFIX)-editenv test.2.result.env create
	@$(GRUB_PREFIX)-editenv test.2.result.env set debug=all,-scripting,-lexer
	@truncate -s 512 test.2.result.env
	@echo test importing from DMPSTORE and exporting to DMPSTORE and symbolic guid-name validation
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n {grub}-GRUB_ENV -f test.2.result.env -D -e test.2.0.goal.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.2.0.goal.var -e test.2.0.result.var -D
	@cmp test.2.0.result.var test.2.0.result.var
	@rm test.2.0.result.*
	@echo passed
	@echo test importing from DMPSTORE and exporting to libefivar
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n {grub}-GRUB_ENV -f test.2.result.env -D -e test.2.1.goal.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.2.1.goal.var -e test.2.1.result.var
	@cmp test.2.1.result.var test.2.1.result.var
	@rm test.2.1.result.*
	@echo passed
	@echo test importing from libefivar and exporting to DMPSTORE and mixed-case guid-name validation
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n 91376aff-cBa6-42bE-949d-06fde81128e8-GRUB_ENV -f test.2.result.env -e test.2.2.goal.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.2.2.goal.var -e test.2.2.result.var -D
	@cmp test.2.2.result.var test.2.2.result.var
	@rm test.2.2.result.*
	@echo passed
	@echo test importing from libefivar and exporting to libefivar and guid-name validation
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -n 91376aff-cba6-42be-949d-06fde81128e8-GRUB_ENV -f test.2.result.env -e test.2.3.goal.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.2.3.goal.var -e test.2.3.result.var
	@cmp test.2.3.result.var test.2.3.result.var
	@rm test.2.3.* test.2.result.env
	@echo passed
	@echo testing efivar -L
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -L | \
		grep -q '^{91376aff-cba6-42be-949d-06fde81128e8} {grub} efi_guid_grub GRUB$$'
	@echo passed

test3:
	@echo testing with BootOrder variable dmpstore generated
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.3.goal.var -e test.3.0.result.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.3.0.result.var -e test.3.1.result.var -D
	@cmp test.3.goal.var test.3.1.result.var
	@rm test.3.?.result.var
	@echo passed

test4:
	@echo testing with ConIn variable dmpstore generated
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.4.goal.var -e test.4.0.result.var
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFIVAR) -i test.4.0.result.var -e test.4.1.result.var -D
	@cmp test.4.goal.var test.4.1.result.var
	@rm test.4.?.result.var
	@echo passed

test5:
	@echo testing threading in libefivar
	@TOPDIR=$(TOPDIR) $(TOPDIR)/tests/test-threading

test6:
	@echo testing ESL creation with sha256 sums
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) -g {redhat} -t sha256 -a \
		-h 87428fc522803d31065e7bce3cf03fe475096631e5e07bbd7a0fde60c4cf25c7 \
		-h 0263829989b6fd954f72baaf2fc64bc2e2f01d692d4de72986ea808f6e99813f \
		-h a3a5e715f0cc574a73c3f9bebb6bc24f32ffd5b67b387244c2c909da779a1478 \
		-h 8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be \
		-f -o test.5.result.esl
	@cmp test.5.goal.esl test.5.result.esl
	@rm test.5.result.esl
	@echo passed

test7:
	@echo testing ESL entry removal with sha256 sums
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) -g {redhat} -t sha256 \
		-i test.5.goal.esl -r \
		-h a3a5e715f0cc574a73c3f9bebb6bc24f32ffd5b67b387244c2c909da779a1478 \
		-f -o test.6.result.esl
	@cmp test.6.goal.esl test.6.result.esl
	@rm test.6.result.esl
	@echo passed

test8:
	@echo testing adding a sha256 sum to an existing ESL
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) -g {redhat} -t sha256 \
		-i test.6.goal.esl -a \
		-h a3a5e715f0cc574a73c3f9bebb6bc24f32ffd5b67b387244c2c909da779a1478 \
		-f -o test.7.result.esl
	@cmp test.5.goal.esl test.7.result.esl
	@rm test.7.result.esl
	@echo passed

test9:
	@echo testing ESL entry addition with x509 cert
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) -g {redhat} -t sha256 \
		-i test.5.goal.esl -a -c test.8.cert.cer \
		-f -o test.8.result.esl
	@cmp test.8.goal.esl test.8.result.esl
	@rm test.8.result.esl
	@echo passed

test10:
	@echo testing ESL entry removal with x509 cert
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) -g {redhat} -t sha256 \
		-i test.8.goal.esl -r -c test.8.cert.cer \
		-f -o test.9.result.esl
	@cmp test.5.goal.esl test.9.result.esl
	@rm test.9.result.esl
	@echo passed

test11:
	@echo testing ESL dumping with x509 + sha256 sums
	@LD_LIBRARY_PATH=$(TOPDIR)/src $(EFISECDB) \
		-i test.8.goal.esl -A > test10.result.txt
	@cmp test.10.goal.txt test.8.result.txt
	@rm test.8.result.txt
	@echo passed

.PHONY: all clean $(TESTS)

# vim:ft=make
#
