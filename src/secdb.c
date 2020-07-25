// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * secdb.c - management of EFI security databases
 * Copyright Peter Jones <pjones@redhat.com>
 * Copyright Red Hat, Inc.
 */

#include "efisec.h"

/*
 * create a new in-memory signature list
 */
PUBLIC efi_secdb_t *
efi_secdb_new(void)
{
	debug("Allocating new secdb");
	efi_secdb_t *secdb = calloc(1, sizeof (*secdb));
	if (!secdb) {
		efi_error("Could not allocate %zd bytes of memory", sizeof(*secdb));
		return NULL;
	}
	INIT_LIST_HEAD(&secdb->list);
	INIT_LIST_HEAD(&secdb->entries);

	efi_secdb_set_bool(secdb, EFI_SECDB_SORT, true);

	return secdb;
}

/*
 * find the secdb entry for a given size and algorithm, or return NULL and set
 * errno to ENOENT if there aren't any.
 */
static inline efi_secdb_t *
find_secdb_entry(efi_secdb_t *top, efi_secdb_type_t algorithm, size_t datasz)
{
	efi_secdb_t *secdb = NULL;
	list_t *pos;
	size_t sigsz = (algorithm == X509_CERT)
		       ? datasz
		       : secdb_entry_size_from_type(algorithm);
	char *algstr = NULL;

	efi_guid_to_id_guid(secdb_guid_from_type(algorithm), &algstr);
	debug("searching for entry with type:%s sz:%zd datasz:%zd", algstr, sigsz, datasz);
	xfree(algstr);
	for_each_secdb_prev(pos, &top->list) {
		efi_secdb_t *candidate;

		candidate = list_entry(pos, efi_secdb_t, list);

		if (candidate->listsz == 0 ||
		    candidate->algorithm == MAX_SECDB_TYPE ||
		    (candidate->algorithm == algorithm &&
		     candidate->sigsz == sigsz)) {
			secdb = candidate;
			debug("found secdb %p", secdb);
			return secdb;
		}
	}

	errno = ENOENT;
	return NULL;
}

static inline efi_secdb_t *
alloc_secdb_entry(efi_secdb_t *top,
		  efi_secdb_type_t algorithm,
		  size_t datasz)
{
	efi_secdb_t *secdb = NULL;
	size_t sigsz = (algorithm == X509_CERT)
		       ? datasz
		       : secdb_entry_size_from_type(algorithm);

	debug("allocating new secdb entry alg %d", algorithm);
	secdb = efi_secdb_new();
	if (!secdb)
		return NULL;

	INIT_LIST_HEAD(&secdb->entries);
	INIT_LIST_HEAD(&secdb->list);
	secdb->algorithm = algorithm;
	secdb->hdrsz = secdb_header_size_from_type(algorithm);
	secdb->sigsz = sigsz;
	secdb->flags = top->flags;
	debug("Adding secdb:%p to top:%p with hdrsz:%zd sigsz:%zd",
	      secdb, top, secdb->hdrsz, secdb->sigsz);
	list_add_tail(&secdb->list, &top->list);

	return secdb;
}

/*
 * find the secdb entry for a given size and algorithm, or allocate and
 * initialize a new one if there aren't any.
 */
static inline efi_secdb_t *
find_or_alloc_secdb_entry(efi_secdb_t *top,
			  efi_secdb_type_t algorithm,
			  size_t datasz)
{
	efi_secdb_t *secdb = NULL;
	size_t sigsz = (algorithm == X509_CERT)
		       ? datasz
		       : secdb_entry_size_from_type(algorithm);

	secdb = find_secdb_entry(top, algorithm, datasz);
	if (!secdb) {
		debug("could not find secdb entry of alg:%d datasz:%zd",
		      algorithm, datasz);
		secdb = alloc_secdb_entry(top, algorithm, datasz);
		if (!secdb)
			return NULL;
	}
	secdb->algorithm = algorithm;
	secdb->sigsz = sigsz;

	return secdb;
}

/*
 * delete an entry from our internal representation
 */
PUBLIC int
efi_secdb_del_entry(efi_secdb_t *top,
		    const efi_guid_t *owner,
		    efi_secdb_type_t algorithm,
		    efi_secdb_data_t *data,
		    size_t datasz)
{
	efi_secdb_t *secdb;
	list_t *pos;
	size_t sigsz = (algorithm == X509_CERT)
		       ? datasz
		       : secdb_entry_size_from_type(algorithm);
	bool has_owner = false;

	if (secdb_entry_has_owner_from_type(algorithm, &has_owner) <0)
		return -1;

	if (has_owner)
		sigsz -= sizeof(efi_guid_t);

	if (!top || !owner || !data || !datasz) {
		errno = EINVAL;
		return -1;
	}

	secdb = find_secdb_entry(top, algorithm, datasz);
	if (!secdb)
		return -1;

	for_each_secdb_entry(pos, &secdb->entries) {
		secdb_entry_t *entry = list_entry(pos, secdb_entry_t, list);

		if (!memcmp(data, &entry->data, sigsz) &&
		    !efi_guid_cmp(owner, &entry->owner)) {
			list_del(&entry->list);
			free(entry);
			break;
		}
	}

	return 0;
}

static int
secdb_add_entry_data(efi_secdb_t *secdb,
		     const efi_guid_t * const owner,
		     efi_secdb_data_t *data, uint32_t datasz)
{
	secdb_entry_t *new;
	size_t allocsz;

	if (!secdb || !owner || !data || !datasz) {
		errno = EINVAL;
		return -1;
	}

	allocsz = offsetof(secdb_entry_t, data) + datasz;
	new = calloc(1, allocsz);
	if (!new)
		return -1;

	INIT_LIST_HEAD(&new->list);
	memcpy(&new->data, data, datasz);
	memcpy(&new->owner, owner, sizeof(efi_guid_t));
	debug("Adding to secdb:%p entry:%p owner:%p data:%p-%p datasz:%zd",
	      secdb, new, &new->owner, &new->data, &new->data+datasz, datasz);
	list_add_tail(&new->list, &secdb->entries);
	debug("nsigs:%zd -> %zd", secdb->nsigs, secdb->nsigs+1);
	secdb->nsigs += 1;
	if (secdb->nsigs == 1 &&
	    secdb->algorithm == X509_CERT &&
	    secdb->sigsz == sizeof(efi_guid_t)) {
		debug("secdb->sigsz:%zd -> %zd",
		      secdb->sigsz, secdb->sigsz + datasz);
		secdb->sigsz += datasz;
	}

	size_t sz = secdb_entry_size(secdb);
	secdb->listsz = sz;

	return 0;
}

int
efi_secdb_add_entry_or_secdb(efi_secdb_t *top,
			     const efi_guid_t *owner,
			     efi_secdb_type_t algorithm,
			     efi_secdb_data_t *data,
			     size_t datasz,
			     bool force_new_secdb)
{
	list_t *pos;
	efi_secdb_t *secdb = NULL;
	bool has_owner = false;
	size_t sigsz;

	if (!top) {
		errno = EINVAL;
		efi_error("invalid efi_secdb_t %p", top);
		return -1;
	}

	if (secdb_entry_has_owner_from_type(algorithm, &has_owner) < 0)
		return -1;

	sigsz = datasz + has_owner ? sizeof(*owner) : 0;

	if (force_new_secdb) {
		debug("forcing new secdb entry (has_owner:%d)", has_owner);
		secdb = alloc_secdb_entry(top, algorithm, sigsz);
		secdb->algorithm = algorithm;
		secdb->sigsz = datasz;
	} else {
		secdb = find_or_alloc_secdb_entry(top, algorithm, datasz);
		debug("finding secdb alg:%d datasz:%zd sigsz:%zd has_owner:%d",
		      algorithm, datasz, sigsz, has_owner);
	}
	if (!secdb)
		return -1;

	for_each_secdb_entry(pos, &secdb->entries) {
		secdb_entry_t *entry = list_entry(pos, secdb_entry_t, list);
		if (!memcmp(data, &entry->data, datasz))
			return 0;
	}

	debug("adding %zd bytes of data", datasz);
	secdb_add_entry_data(secdb, owner, data, datasz);
	if (secdb->flags & (1ul << EFI_SECDB_SORT)) {
		if (secdb->sigsz)
			list_sort(&secdb->entries, secdb_entry_cmp, &datasz);
		list_sort(&top->list, secdb_cmp, NULL);
	}

	return 0;
}

/*
 * add an entry to our internal representation
 */
PUBLIC int
efi_secdb_add_entry(efi_secdb_t *top,
		    const efi_guid_t *owner,
		    efi_secdb_type_t algorithm,
		    efi_secdb_data_t *data,
		    size_t datasz)
{
	return efi_secdb_add_entry_or_secdb(top, owner, algorithm, data, datasz, false);
}

int PUBLIC
efi_secdb_set_bool(efi_secdb_t *secdb,
		   efi_secdb_flag_t flag, bool value)
{
	if (!secdb) {
		efi_error("invalid secdb");
		errno = EINVAL;
		return -1;
	}

	if (flag < 0 || flag >= EFI_SECDB_INVALID) {
		efi_error("invalid flag '%d'", flag);
		errno = EINVAL;
		return -1;
	}

	if (value)
		secdb->flags |= (1ul << flag);
	else
		secdb->flags &= ~(1ul << flag);

	return 0;
}

/*
 * parse a signature list file into our internal representation
 */
PUBLIC int
efi_secdb_parse(uint8_t *data, size_t datasz, efi_secdb_t **secdbp)
{
	esl_iter *iter = NULL;
	int rc;
	efi_secdb_t *secdb;
	bool new_secdb = false;
	bool sort = false;

	if (!data || !datasz) {
		efi_error("Invalid secdb data (data=%p datasz=%zd)",
			  data, datasz);
		errno = EINVAL;
		return -1;
	}

	if (!secdbp) {
		efi_error("Invalid secdb pointer");
		errno = EINVAL;
		return -1;
	}

	secdb = *secdbp;
	if (!secdb) {
		secdb = efi_secdb_new();
		if (!secdb)
			return -1;
		new_secdb = true;
	}
	sort = secdb->flags & (1ul << EFI_SECDB_SORT);

	debug("adding %zd bytes to secdb %p", datasz, secdb);

	rc = esl_iter_new(&iter, data, datasz);
	if (rc < 0) {
		efi_error("Could not iterate security database");
		return rc;
	}

	do {
		uint8_t *sig = NULL;
		size_t sigsz = 0;
		efi_guid_t secdb_type_guid, owner;
		efi_secdb_type_t secdb_type;
		bool corrected = false;
		bool force = false;

		rc = esl_iter_next(iter, &secdb_type_guid, &owner,
					 &sig, &sigsz);
		if (rc < 0 && errno == EOVERFLOW) {
			debug("esl_iter_next is malformed; attempting correction");
			corrected = true;
			rc = esl_iter_next_with_size_correction(iter,
					&secdb_type_guid, &owner, &sig, &sigsz,
					true);
			debug("got new entry with sigsz:%zd", sigsz);
		}
		if (rc < 0) {
			efi_error("Could not get next security database entry");
			esl_iter_end(iter);
			return rc;
		}
		if (rc == ESL_ITER_DONE)
			break;

		if (new_secdb)
			secdb->sigsz = sigsz;
		debug("sigsz:%zd", sigsz);
                secdb_type = secdb_entry_type_from_guid(&secdb_type_guid);
		debug("secdb_type:%d", secdb_type);

		if (corrected)
			force = true;
		if (rc == ESL_ITER_NEW_LIST && !sort)
			force = true;
		if (new_secdb)
			force = false;

		if (force) {
			if (corrected)
				debug("forcing new secdb due to size correction");
			else if (rc == ESL_ITER_NEW_LIST && !sort)
				debug("forcing new secdb due to new input ESL --no-sort");
			else
				debug("wth?  why is force set");
		}

		efi_secdb_add_entry_or_secdb(secdb, &owner, secdb_type,
					     (efi_secdb_data_t *)sig, sigsz,
					     force);
		new_secdb = false;
	} while (rc > 0);

	esl_iter_end(iter);

	if (sort)
		list_sort(&secdb->list, secdb_cmp, NULL);

	*secdbp = secdb;
	return 0;
}

struct visitor_state {
	unsigned int listnum;
	unsigned int signum;

	efi_signature_list_t *esl;

	char *buf;
	size_t pos;
};

/*
 * realize a signature list file from our internal representation into
 */
static efi_secdb_visitor_status_t
secdb_realize_visitor(unsigned int listnum, unsigned int signum,
		      const efi_guid_t * const owner,
		      const efi_secdb_type_t algorithm,
		      const void * const header,
		      const size_t headersz,
		      const efi_secdb_data_t * const data,
		      const size_t datasz,
		      void *closure)
{
	struct visitor_state *state = closure;
	const efi_guid_t *alg = secdb_guid_from_type(algorithm);
	char *buf;
	size_t allocsz, esdsz;
	ptrdiff_t skew;
	efi_signature_list_t *esl;
	efi_signature_data_t *esd;

	esdsz = sizeof(efi_guid_t) + datasz;

	debug("listnum:%d signum:%d", listnum, signum);
	if (listnum > state->listnum || signum == 0) {
		allocsz = ALIGN_UP(state->pos
				   + sizeof(state->esl)
				   + headersz
				   + esdsz,
				   page_size);
		buf = realloc(state->buf, allocsz);
		skew = buf - state->buf;
		if (!buf) {
			efi_error("could not allocate %zd bytes", allocsz);
			return ERROR;
		}
		esl = (efi_signature_list_t *)
			(buf + state->pos);
		state->buf = buf;
		state->esl = esl;
		memset(buf + state->pos, 0, allocsz - state->pos);

		memcpy(&esl->signature_type, alg, sizeof(efi_guid_t));
		esl->signature_list_size = sizeof(efi_signature_list_t) + headersz;
		esl->signature_header_size = headersz;
		esl->signature_size = esdsz;
		size_t pos = ((char *)esl
			      + offsetof(efi_signature_list_t, signature_size)
			      + sizeof(esl->signature_size)) - buf;
		state->pos = pos;
		if (header && headersz > 0)
			memcpy(buf+state->pos, header, headersz);
		state->pos += headersz;
		esd = (efi_signature_data_t *)(buf + state->pos);
		debug("esl[%u]:%p esd[%u]:%p", listnum, esl, signum, esd);
	} else {
		allocsz = ALIGN_UP(state->pos + esdsz,
				   page_size);
		buf = realloc(state->buf, allocsz);
		if (!buf) {
			efi_error("could not allocate %zd bytes", allocsz);
			return ERROR;
		}
		skew = buf - state->buf;
		memset(buf + state->pos, 0, allocsz - state->pos);
		esl = (efi_signature_list_t *)
			((char *)state->esl + skew);
		state->buf = buf;
		state->esl = esl;
		esd = (efi_signature_data_t *)(buf + state->pos);
		debug("esl[%u]:%p esd[%u]:%p", listnum, esl, signum, esd);
	}

	memcpy(&esd->signature_owner, owner, sizeof(efi_guid_t));
	memcpy(&esd->signature_data[0], data, datasz);
	state->pos += esdsz;
	esl->signature_list_size += esdsz;

	return CONTINUE;
}

/*
 * realize a signature list file from our internal representation
 */
PUBLIC int
efi_secdb_realize(efi_secdb_t *secdb, void **out, size_t *outsize)
{

	struct visitor_state state = { 0, };

	state.buf = calloc(1, page_size);
	state.esl = (efi_signature_list_t *)state.buf;
	if (!state.buf) {
		efi_error("could not allocate %zd bytes", page_size);
		return ERROR;
	}

	efi_secdb_visit_entries(secdb, secdb_realize_visitor, &state);

	*out = state.buf;
	*outsize = state.pos;

	return 0;
}

/*
 * Free a single secdb and all of its components, but not other
 * linked secdb enties
 */
void
secdb_free_entry(efi_secdb_t *secdb)
{
	list_t *pos = NULL, *tmp = NULL;

	if (!secdb)
		return;

	for_each_secdb_entry_safe(pos, tmp, &secdb->entries) {
		secdb_entry_t *entry = list_entry(pos, secdb_entry_t, list);
		bool has_owner = true;
		int rc;

		rc = secdb_entry_has_owner_from_type(secdb->algorithm, &has_owner);
		if (rc < 0)
			efi_error("could not determine signature type");

		list_del(&entry->list);
		//memset(&entry->data, 0, secdb->sigsz - (has_owner ? sizeof(efi_guid_t) : 0));
		xfree(entry);
	}

	memset(secdb, 0, sizeof(*secdb));
	xfree(secdb);
}

/*
 * free a whole list of secdb entries
 */
PUBLIC void
efi_secdb_free(efi_secdb_t *top)
{
	list_t *pos = NULL, *tmp = NULL;

	if (!top)
		return;

	for_each_secdb_safe(pos, tmp, &top->list) {
		efi_secdb_t *secdb = list_entry(pos, efi_secdb_t, list);
		list_del(&secdb->list);
		secdb_free_entry(secdb);
	}
	free(top);
}

static efi_secdb_visitor_status_t
secdb_visit_entries(efi_secdb_t *secdb, int i,
		    efi_secdb_visitor_t *visitor,
		    void *closure)
{
	int j = 0;
	list_t *pos;
	size_t datasz;
	bool has_owner = true;
	int rc;

	rc = secdb_entry_has_owner_from_type(secdb->algorithm, &has_owner);
	if (rc < 0) {
		efi_error("could not determine signature type");
		return ERROR;
	}
	datasz = secdb->sigsz
		 - (has_owner ? sizeof(efi_guid_t) : 0);

	for_each_secdb_entry(pos, &secdb->entries) {
		secdb_entry_t *entry = list_entry(pos, secdb_entry_t, list);
		efi_secdb_visitor_status_t status;

		debug("secdb[%d]:%p entry[%d]:%p pos:%p = {%p, %p}", i, secdb, j, entry, pos, pos ? pos->prev : 0, pos ? pos->next : 0);
		debug("secdb[%d]:%p entry[%d]:%p owner:%p data:%p-%p datasz:%zd", i, secdb, j, entry, &entry->owner, &entry->data, &entry->data+datasz, datasz);
		status = visitor(i, j++, &entry->owner,
				 secdb->algorithm,
				 NULL, 0,
				 &entry->data, datasz,
				 closure);
		if (status == ERROR)
			return ERROR;
		if (status == BREAK)
			return BREAK;
	}
	return CONTINUE;
}

PUBLIC int
efi_secdb_visit_entries(efi_secdb_t *top,
			efi_secdb_visitor_t *visitor,
			void *closure)
{
	efi_secdb_visitor_status_t status = CONTINUE;
	list_t *pos = NULL, *tmp = NULL;
	int i = 0;

	for_each_secdb_safe(pos, tmp, &top->list) {
		efi_secdb_t *secdb = list_entry(pos, efi_secdb_t, list);

		debug("secdb[%d]:%p pos:%p = {%p, %p}", i, secdb, pos, pos ? pos->prev : 0, pos ? pos->next : 0);
		debug("secdb[%d]:%p nsigs:%d sigsz:%d", i, secdb, secdb->nsigs, secdb->sigsz);
		status = secdb_visit_entries(secdb, i++, visitor, closure);
		if (status == ERROR)
			return -1;
		if (status == BREAK)
			break;
	}
	return 0;
}

/*
 * compare secdb_entry_t items
 */
int
secdb_entry_cmp(const void *ap, const void *bp, void *state)
{
	const secdb_entry_t *a = *(const secdb_entry_t **)ap;
	const secdb_entry_t *b = *(const secdb_entry_t **)bp;
	size_t sigsz = *(size_t *)state;
	int rc;

	rc = efi_guid_cmp(&a->owner, &b->owner);
	if (rc != 0)
		return rc;

	return memcmp(a->data.raw, b->data.raw, sigsz);
}

/*
 * compare efi_secdb_t items
 */
int
secdb_cmp(const void *ap, const void *bp, void * state UNUSED)
{
	const efi_secdb_t *a = *(efi_secdb_t **)ap;
	const efi_secdb_t *b = *(efi_secdb_t **)bp;

	if (ap == NULL || bp == NULL)
		return bp - ap;

	if (a->algorithm == MAX_SECDB_TYPE) {
		debug("sorting unready data from secdb:%p", a);
		return -1;
	}

	if (b->algorithm == MAX_SECDB_TYPE) {
		debug("sorting unready data from secdb:%p", b);
		return 1;
	}

	if (a->algorithm != b->algorithm) {
		return b->algorithm - a->algorithm;
	}

	if (a->sigsz != b->sigsz) {
		return a->sigsz - b->sigsz;
	}

	return a->listsz - b->listsz;
}

const secdb_alg_t PUBLIC efi_secdb_algs_[MAX_SECDB_TYPE] = {
	[SHA1] = {
		.class = HASH,
		.guid = &efi_guid_sha1,
		.header_size = 0,
		.has_owner = true,
		.size = 20
	},
	[SHA224] = {
		.class = HASH,
		.guid = &efi_guid_sha224,
		.header_size = 0,
		.has_owner = true,
		.size = 28,
	},
	[SHA256] = {
		.class = HASH,
		.guid = &efi_guid_sha256,
		.header_size = 0,
		.has_owner = true,
		.size = 32,
	},
	[SHA384] = {
		.class = HASH,
		.guid = &efi_guid_sha384,
		.header_size = 0,
		.has_owner = true,
		.size = 48,
	},
	[SHA512] = {
		.class = HASH,
		.guid = &efi_guid_sha512,
		.header_size = 0,
		.has_owner = true,
		.size = 64,
	},
	[RSA2048] = {
		.class = SIGNATURE,
		.guid = &efi_guid_rsa2048,
		.header_size = 0,
		.has_owner = true,
		.size = 256,
	},
	[RSA2048_SHA1] = {
		.class = SIGNATURE,
		.guid = &efi_guid_rsa2048_sha1,
		.header_size = 0,
		.has_owner = true,
		.size = 256,
	},
	[RSA2048_SHA256] = {
		.class = SIGNATURE,
		.guid = &efi_guid_rsa2048_sha256,
		.header_size = 0,
		.has_owner = true,
		.size = 256,
	},
        [X509_SHA256] = {
                .class = CERTIFICATE_HASH,
                .guid = &efi_guid_x509_sha256,
		.header_size = 0,
		.has_owner = true,
                .size = 256,
        },
        [X509_SHA384] = {
                .class = CERTIFICATE_HASH,
                .guid = &efi_guid_x509_sha384,
		.header_size = 0,
		.has_owner = true,
                .size = 384,
        },
        [X509_SHA512] = {
                .class = CERTIFICATE_HASH,
                .guid = &efi_guid_x509_sha512,
		.header_size = 0,
		.has_owner = true,
                .size = 512,
        },
	[X509_CERT] = {
		.class = CERTIFICATE,
		.guid = &efi_guid_x509_cert,
		.header_size = 0,
		.has_owner = true,
		.size = 0,
	},
};

const size_t num_efi_secdb_algs_ = sizeof (efi_secdb_algs_) / sizeof (secdb_alg_t);
