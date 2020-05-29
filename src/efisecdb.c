// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * efisecdb.c - efi signature list management tool
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */
#include "fix_coverity.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "efisec.h"

extern char *optarg;
extern int optind, opterr, optopt;

struct hash_param {
	char *name;
	efi_secdb_type_t algorithm;
	ssize_t size;
	bool def;
};

static struct hash_param hash_params[] = {
	{.name = "sha512",
	 .algorithm = SHA512,
	 .size = 64,
	 .def = false,
	},
	{.name = "sha256",
	 .algorithm = SHA256,
	 .size = 32,
	 .def = true,
	},
	{.name = "sha1",
	 .algorithm = SHA1,
	 .size = 20,
	 .def = false,
	},
};
static int n_hash_params = sizeof (hash_params) / sizeof (hash_params[0]);

static void
set_hash_parameters(char *name, int *hash_number)
{
	FILE *out;
	int def = -1;

	if (strcmp(name, "help")) {
		out = stderr;
		for (int i = 0; i < n_hash_params; i++) {
			if (!strcmp(name, hash_params[i].name)) {
				*hash_number = i;
				return;
			}
		}
	} else {
		out = stdout;
	}

	if (out == stderr)
		warnx("Invalid hash type \"%s\"", name);
	fprintf(out, "Supported hashes:");
	for (int i = 0; i < n_hash_params; i++) {
		fprintf(out, " %s", hash_params[i].name);
		if (hash_params[i].def)
			def = i;
	}
	fprintf(out, "\n");
	if (def >= 0)
		fprintf(out, "Default hash is %s\n", hash_params[def].name);
	exit(out == stderr ? 1 : 0);
}

static int verbose_errors = 0;

static void
show_errors(void)
{
	int rc = 1;

	if (!verbose_errors)
		return;

	printf("Error trace:\n");
	for (int i = 0; rc > 0; i++) {
		char *filename = NULL;
		char *function = NULL;
		int line = 0;
		char *message = NULL;
		int error = 0;

		rc = efi_error_get(i, &filename, &function, &line, &message,
				   &error);
		if (rc < 0)
			err(1, "error fetching trace value");
		if (rc == 0)
			break;
		printf(" %s:%d %s(): %s: %s", filename, line, function,
		       strerror(error), message);
	}
}

static void
secdb_warnx(const char * const fmt, ...)
{
	va_list ap;
	int errnum = errno;

	fflush(stdout);
	fprintf(stderr, "%s: ", program_invocation_short_name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errno = errnum;
	fprintf(stderr, "\n");
	show_errors();
}

static void NORETURN
secdb_err(int status, const char * const fmt, ...)
{
	va_list ap;
	int errnum = errno;

	fflush(stdout);
	fprintf(stderr, "%s: ", program_invocation_short_name);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	errno = errnum;
	fprintf(stderr, ": %m\n");
	show_errors();
	exit(status);
}

static void NORETURN
secdb_errx(int status, const char * const fmt, ...)
{
	va_list ap;
	int errnum = errno;

	fflush(stdout);
	fprintf(stderr, "%s: ", program_invocation_short_name);
	va_start(ap, fmt);
	errno = errnum;
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	show_errors();
	exit(status);
}

static void NORETURN
usage(int status)
{
	fprintf(status == 0 ? stdout : stderr,
		"Usage: %s [OPTION...]\n"
		"  -i, --infile=<file>       input database\n"
		"  -o, --outfile=<file>      output database\n"
		"  -a, --add                 following hashes or certs are to be added (default)\n"
		"  -r, --remove              following hashes or certs are to be removed\n"
		"  -g, --owner-guid=<GUID>   following added entries use GUID as the owner\n"
		"  -h, --hash=<hash>         hash value to add (\n"
		"  -t, --type=<hash-type>    hash type to add (\"help\" lists options)\n"
		"  -c, --certificate=<file>  certificate file to add\n",
		program_invocation_short_name);
	exit(status);
}

typedef enum {
	ADD,
	REMOVE
} action_type_t;

typedef struct {
	list_t list;

	action_type_t action;
	efi_guid_t owner;
	efi_secdb_type_t algorithm;
	uint8_t *data;
	size_t datasz;
} action_t;
#define for_each_action(pos, head) list_for_each(pos, head)
#define for_each_action_safe(pos, n, head) list_for_each_safe(pos, n, head)

static void
add_action(list_t *list, action_type_t action_type,
	   const efi_guid_t *owner,
	   efi_secdb_type_t algorithm, uint8_t *data, size_t datasz)
{
	action_t *action;

	if (action_type == ADD && efi_guid_is_empty(owner))
		errx(1, "no owner spefified for --add");

	action = calloc(1, sizeof(action_t));
	if (!action)
		err(1, "could not allocate memory");
	action->action = action_type;
	action->owner = *owner;
	action->algorithm = algorithm;
	action->data = data;
	action->datasz = datasz;
	list_add_tail(&action->list, list);
}

static void
free_actions(int status UNUSED, void *actionsp)
{
	list_t *actions = (list_t *)actionsp;
	list_t *pos, *tmp;

	for_each_action_safe(pos, tmp, actions) {
		action_t *action = list_entry(pos, action_t, list);

		list_del(&action->list);
		xfree(action->data);
		free(action);
	}
}

static void
free_infiles(int status UNUSED, void *infilesp)
{
	list_t *infiles = (list_t *)infilesp;
	list_t *pos, *tmp;

	for_each_ptr_safe(pos, tmp, infiles) {
		ptrlist_t *entry = list_entry(pos, ptrlist_t, list);

		xfree(entry->ptr);
		list_del(&entry->list);
		free(entry);
	}
}

static void
maybe_free_secdb(int status UNUSED, void *voidp)
{
	efi_secdb_t **secdbp = (efi_secdb_t **)voidp;

	if (secdbp == NULL || *secdbp == NULL)
		return;

	efi_secdb_free(*secdbp);
}

static void
maybe_do_unlink(int status, void *filep)
{
	char **file = (char **)filep;

	if (status == 0)
		return;
	if (file == NULL || *file == NULL)
		return;

	unlink(*file);
}

static void
check_hash_index(int hash_index)
{
	if (hash_index < 0 || hash_index >= n_hash_params)
		errx(1, "hash type is not set");
}

static efi_secdb_t *secdb;
static list_t infiles;
static list_t actions;
static char *outfile = NULL;

int
main(int argc, char *argv[])
{
	efi_guid_t owner = efi_guid_empty;
	int rc;
	action_type_t mode = ADD;
	list_t *pos, *tmp;
	int c, i;
	int hash_index = -1;
	bool force = false;
	int verbose = 0;
	bool dump = false;
	bool annotate = false;
	bool wants_add_actions = false;
	int status = 0;

	const char sopts[] = ":aAc:dfg:h:i:o:rt:v?";
	const struct option lopts[] = {
		{"add", no_argument, NULL, 'a' },
		{"annotate", no_argument, NULL, 'A' },
		{"certificate", required_argument, NULL, 'c' },
		{"dump", no_argument, NULL, 'd' },
		{"force", no_argument, NULL, 'f' },
		{"owner-guid", required_argument, NULL, 'g' },
		{"hash", required_argument, NULL, 'h' },
		{"infile", required_argument, NULL, 'i' },
		{"outfile", required_argument, NULL, 'o' },
		{"remove", no_argument, NULL, 'r' },
		{"type", required_argument, NULL, 't' },
		{"verbose", no_argument, NULL, 'v' },
		{"usage", no_argument, NULL, '?' },
		{"help", no_argument, NULL, '?' },
		{NULL, 0, NULL, '\0' }
	};

	INIT_LIST_HEAD(&infiles);
	INIT_LIST_HEAD(&actions);

	on_exit(free_actions, &actions);
	on_exit(free_infiles, &infiles);
	on_exit(maybe_free_secdb, &secdb);
	on_exit(maybe_do_unlink, &outfile);

	/*
	 * parse the command line.
	 *
	 * note that we don't really process the security database inputs,
	 * here, and the cert and hash add/remove must be kept in order as
	 * supplied.
	 */
	opterr = 0;
	while ((c = getopt_long(argc, argv, sopts, lopts, &i)) != -1) {
		uint8_t *data;
		ssize_t datasz;

		switch (c) {
		case 'a':
			mode = ADD;
			break;
		case 'A':
			dump = true;
			annotate = true;
			break;
		case 'c':
			if (optarg == NULL)
				secdb_errx(1, "--certificate requires a value");
			datasz = get_file(&data, "%s", optarg);
			if (datasz < 0)
				secdb_err(1, "could not read certificate \"%s\"",
					  optarg);
			datasz -= 1;

			// this is arbitrary but still much too small
			if (datasz < 16)
				secdb_err(1, "certificate \"%s\" is invalid",
					  optarg);

			debug("%s certificate of %d bytes", mode == ADD ? "adding" : "removing", datasz);
			if (mode == ADD)
				wants_add_actions = true;
			add_action(&actions, mode, &owner, X509_CERT, data, datasz);
			break;
		case 'd':
			dump = true;
			break;
		case 'f':
			force = true;
			break;
		case 'g':
			if (optarg == NULL)
				secdb_errx(1, "--owner-guid requires a value");
			rc = efi_id_guid_to_guid(optarg, &owner);
			if (rc < 0)
				secdb_errx(1, "could not parse guid \"%s\"", optarg);
			break;
		case 'h':
			if (optarg == NULL)
				secdb_errx(1, "--hash requires a value");
			check_hash_index(hash_index);
			datasz = strlen(optarg);
			if (datasz != hash_params[hash_index].size * 2)
				secdb_errx(1,
					   "hash \"%s\" requires a %zd-bit value, but supplied value is %zd bits",
					   hash_params[hash_index].name,
					   hash_params[hash_index].size * 8,
					   datasz * 4);
			datasz >>= 1;
			data = hex_to_bin(optarg, datasz);
			debug("%s hash %s", mode == ADD ? "adding" : "removing", optarg);
			if (mode == ADD)
				wants_add_actions = true;
			add_action(&actions, mode, &owner,
				   hash_params[hash_index].algorithm,
				   data, datasz);
			break;
		case 'i':
			if (optarg == NULL)
				secdb_errx(1, "--infile requires a value");
			ptrlist_add(&infiles, optarg);
			break;
		case 'o':
			if (outfile)
				secdb_errx(1, "--outfile cannot be used multiple times.");
			if (optarg == NULL)
				secdb_errx(1, "--outfile requires a value");
			outfile = optarg;
			break;
		case 'r':
			mode = REMOVE;
			break;
		case 't':
			if (optarg == NULL)
				secdb_errx(1, "--type requires a value");
			set_hash_parameters(optarg, &hash_index);
			break;
		case 'v':
			if (optarg) {
				long v;

				errno = 0;
				v = strtol(optarg, NULL, 0);
				verbose = (errno == ERANGE) ? verbose + 1 : v;
			} else {
				verbose += 1;
			}
			break;
		case '?':
			usage(0);
			break;
		case ':':
			if (optarg != NULL)
				errx(1, "option '%c' does not take an argument (\"%s\")", optopt, optarg);
		}
	}

	setenv("NSS_DEFAULT_DB_TYPE", "sql", 0);
	efi_set_verbose(verbose, stderr);
	if (verbose) {
		setvbuf(stdout, NULL, _IONBF, 0);
	}

	if (!outfile && !dump)
		errx(1, "no output specified");
	if (list_empty(&infiles) && !wants_add_actions)
		errx(1, "no input files or database additions");

	secdb = efi_secdb_new();
	if (!secdb)
		err(1, "could not allocate memory");
	debug("top secdb:%p", secdb);

	for_each_ptr_safe(pos, tmp, &infiles) {
		int infd = -1;
		uint8_t *siglist = NULL;
		size_t siglistsz = 0;
		char *infile;
		ptrlist_t *entry = list_entry(pos, ptrlist_t, list);

		infile = entry->ptr;

		debug("adding input file %s", infile);
		infd = open(infile, O_RDONLY);
		if (infd < 0)
			err(1, "could not open \"%s\"", infile);

		rc = read_file(infd, &siglist, &siglistsz);
		if (rc < 0)
			err(1, "could not read \"%s\"", infile);
		siglistsz -= 1;
		close(infd);

		rc = efi_secdb_parse(siglist, siglistsz, &secdb);
		efi_error_clear();
		if (rc < 0) {
			/* haaaack city */
			debug("*****************************");
			debug(" starting over with offset 4");
			debug("*****************************");
			if (siglistsz > 4
			    && !(*(uint32_t *)siglist & ~0x7ffu))
				rc = efi_secdb_parse(&siglist[4], siglistsz-4,
						     &secdb);
			if (rc < 0) {
				secdb_warnx("could not parse input file \"%s\"", infile);
				if (!dump)
					exit(1);
				status = 1;
				xfree(outfile);
				outfile = NULL;
				break;
			}
		}
		xfree(siglist);
		list_del(&entry->list);
		free(entry);
	}

	if (!outfile && !dump)
		errx(1, "no output file specified");

	if (status == 0) {
		for_each_action_safe(pos, tmp, &actions) {
			action_t *action = list_entry(pos, action_t, list);

			if (action->action == ADD) {
				debug("adding %d entry", action->algorithm);
				efi_secdb_add_entry(secdb, &action->owner,
						    action->algorithm,
						    (efi_secdb_data_t *)action->data,
						    action->datasz);
			} else {
				debug("removing %d entry", action->algorithm);
				efi_secdb_del_entry(secdb, &action->owner,
						    action->algorithm,
						    (efi_secdb_data_t *)action->data,
						    action->datasz);
			}
			list_del(&action->list);
			free(action->data);
			free(action);
		}
	}

	if (dump)
		secdb_dump(secdb, annotate);

	if (!outfile)
		exit(status);

	int outfd = -1;
	int flags = O_WRONLY|O_CREAT | (force ? 0 : O_EXCL);

	debug("adding output file %s", outfile);
	outfd = open(outfile, flags, 0600);
	if (outfd < 0)
		err(1, "could not open \"%s\"", outfile);

	rc = ftruncate(outfd, 0);
	if (rc < 0)
		err(1, "could not truncate output file \"%s\"", outfile);

	void *output;
	size_t size = 0;
	rc = efi_secdb_realize(secdb, &output, &size);
	if (rc < 0)
		secdb_err(1, "could not realize signature list");

	rc = write(outfd, output, size);
	if (rc < 0)
		err(1, "could not write signature list");

	close(outfd);
	xfree(output);

	return 0;
}
