.data
	.globl efi_well_known_guids_end
	.balign 16
	.type	efi_well_known_guids_end, %object
	.size	efi_well_known_guids_end, 1
	.set	efi_well_known_guids_end, .Lefi_well_known_guids_end
; efi_well_known_guids_end:
; .section .rodata.ewkg
	.globl efi_well_known_guids
	.balign 16
	.type	efi_well_known_guids, %object
	.size	efi_well_known_guids, .Lefi_well_known_guids_end - efi_well_known_guids
efi_well_known_guids:
.incbin "guids.bin"
.Lefi_well_known_guids_end:
	.balign 1
	.byte 0
.section .rodata.ewkn
	.globl efi_well_known_names_end
	.balign 16
	.type	efi_well_known_names_end, %object
	.size	efi_well_known_names_end, .Lefi_well_known_names_end - efi_well_known_names_end
efi_well_known_names_end:
	.globl efi_well_known_names
	.balign 16
	.type	efi_well_known_names, %object
	.size	efi_well_known_names, .Lefi_well_known_names_end - efi_well_known_names
efi_well_known_names:
.incbin "names.bin"
.Lefi_well_known_names_end:
	.byte 0

#if defined(__linux__) && defined(__ELF__)
#if defined(__CET__) && (defined(__i386__) || defined(__x86_64__))
#include <cet.h>
#endif
.section .note.GNU-stack,"",%progbits
#endif
