// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * libefivar - library for the manipulation of EFI variables
 * Copyright 2012-2013 Red Hat, Inc.
 */

#include "fix_coverity.h"

#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "efivar.h"

efi_guid_t const efi_guid_zero = {0};
efi_guid_t const efi_guid_empty = {0};

struct guidname efi_well_known_guids;
struct guidname efi_well_known_guids_end;
struct guidname efi_well_known_names;
struct guidname efi_well_known_names_end;

static int
cmpguidp(const void *p1, const void *p2)
{
	struct guidname *gn1 = (struct guidname *)p1;
	struct guidname *gn2 = (struct guidname *)p2;

	return memcmp(&gn1->guid, &gn2->guid, sizeof (gn1->guid));
}

static int
cmpnamep(const void *p1, const void *p2)
{
	struct guidname *gn1 = (struct guidname *)p1;
	struct guidname *gn2 = (struct guidname *)p2;

	return memcmp(gn1->name, gn2->name, sizeof (gn1->name));
}

struct guid_aliases {
	char *name;
	char *alias;
};

static struct guid_aliases guid_aliases[] = {
	{ "efi_guid_empty", "efi_guid_zero" },
	{ "efi_guid_redhat_2", "efi_guid_redhat" },
	{ NULL, NULL }
};

static void make_aliases(FILE *symout, FILE *header,
			 const char *alias, const efi_guid_t *guid)
{
	for (unsigned int i = 0; guid_aliases[i].name != NULL; i++) {
		if (!strcmp(guid_aliases[i].alias, alias)) {
			fprintf(symout,
				"\nconst efi_guid_t\n"
				"\t__attribute__((__visibility__ (\"default\")))\n"
				"\t%s = {cpu_to_le32(0x%08x),cpu_to_le16(0x%04hx),"
					"cpu_to_le16(0x%04hx),cpu_to_be16(0x%02hhx%02hhx),"
					"{0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx}};\n\n",
				guid_aliases[i].name,
				guid->a, guid->b, guid->c,
				(guid->d & 0xff), (guid->d & 0xff00)>>8,
				guid->e[0], guid->e[1], guid->e[2],
				guid->e[3], guid->e[4], guid->e[5]);

			fprintf(header,
				"extern const efi_guid_t %s __attribute__((__visibility__ (\"default\")));\n",
				guid_aliases[i].name);
		}
	}
}

int
main(int argc, char *argv[])
{
	if (argc != 6)
		exit(1);

	int guidout, nameout;
	int rc;

	FILE *symout, *header;

	guidout = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (guidout < 0)
		err(1, "could not open \"%s\"", argv[2]);

	nameout = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (nameout < 0)
		err(1, "could not open \"%s\"", argv[3]);

	symout = fopen(argv[4], "w");
	if (symout == NULL)
		err(1, "could not open \"%s\"", argv[4]);
	rc = chmod(argv[4], 0644);
	if (rc < 0)
		warn("chmod(%s, 0644)", argv[4]);

	header = fopen(argv[5], "w");
	if (header == NULL)
		err(1, "could not open \"%s\"", argv[5]);
	rc = chmod(argv[5], 0644);
	if (rc < 0)
		warn("chmod(%s, 0644)", argv[5]);

	struct guidname_index *guidnames = NULL;

	rc = read_guids_at(AT_FDCWD, argv[1], &guidnames);
	if (rc < 0)
		err(1, "could not read \"%s\"", argv[1]);

	struct guidname *outbuf = calloc(guidnames->nguids, sizeof(struct guidname));
	if (!outbuf)
		err(1, "could not allocate memory");

	unsigned int line = guidnames->nguids;
	char *strtab = guidnames->strtab;
	printf("%d lines\n", line-1);

	fprintf(header, "#ifndef EFIVAR_GUIDS_H\n#define EFIVAR_GUIDS_H 1\n\n");

	fprintf(symout, "#include <efivar/efivar.h>\n");
	fprintf(symout, "#include <endian.h>\n");
	fprintf(symout, """\n\
#if BYTE_ORDER == BIG_ENDIAN\n\
#define cpu_to_be32(n) (n)\n\
#define cpu_to_be16(n) (n)\n\
#define cpu_to_le32(n) (__builtin_bswap32(n))\n\
#define cpu_to_le16(n) (__builtin_bswap16(n))\n\
#else\n\
#define cpu_to_le32(n) (n)\n\
#define cpu_to_le16(n) (n)\n\
#define cpu_to_be32(n) (__builtin_bswap32(n))\n\
#define cpu_to_be16(n) (__builtin_bswap16(n))\n\
#endif\n\
""");

	for (unsigned int i = 0; i < line-1; i++) {
		struct guidname_offset *gno = &guidnames->offsets[i];
		char *sym = &strtab[gno->symoff];
		char *name = &strtab[gno->nameoff];

		if (!strcmp(sym, "efi_guid_zzignore-this-guid"))
			break;

		make_aliases(symout, header, sym, &gno->guid);

		fprintf(header, "extern const efi_guid_t %s __attribute__((__visibility__ (\"default\")));\n", sym);

		fprintf(symout, "const efi_guid_t\n"
			"__attribute__((__visibility__ (\"default\")))\n"
			"\t%s = {cpu_to_le32(0x%08x),cpu_to_le16(0x%04hx),"
				"cpu_to_le16(0x%04hx),cpu_to_be16(0x%02hhx%02hhx),"
				"{0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx,0x%02hhx}};\n\n",
			sym,
			gno->guid.a, gno->guid.b, gno->guid.c,
			(gno->guid.d & 0xff), (gno->guid.d & 0xff00)>>8,
			gno->guid.e[0], gno->guid.e[1], gno->guid.e[2],
			gno->guid.e[3], gno->guid.e[4], gno->guid.e[5]);

		outbuf[i].guid = gno->guid;
		strcpy(outbuf[i].symbol, sym);
		strcpy(outbuf[i].name, name);
	}

	fprintf(header, "\n#endif /* EFIVAR_GUIDS_H */\n");
	fclose(header);
	fclose(symout);

	qsort(outbuf, line-1, sizeof (struct guidname), cmpguidp);
	rc = write(guidout, outbuf, sizeof (struct guidname) * (line - 1));
	if (rc < 0)
		err(1, "could not write guids.bin");

	qsort(outbuf, line-1, sizeof (struct guidname), cmpnamep);
	rc = write(nameout, outbuf, sizeof (struct guidname) * (line - 1));
	if (rc < 0)
		err(1, "could not write names.bin");
	close(guidout);
	close(nameout);

	free(guidnames->strtab);
	free(guidnames);

	return 0;
}

// vim:fenc=utf-8:tw=75:noet
