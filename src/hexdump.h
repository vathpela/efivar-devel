// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * libefivar - library for the manipulation of EFI variables
 * Copyright 2018-2020 Peter M. Jones <pjones@redhat.com>
 */
#ifndef STATIC_HEXDUMP_H
#define STATIC_HEXDUMP_H

#include <ctype.h>

static inline unsigned long UNUSED
prepare_hex(void *data, size_t size, char *buf, int position)
{
	char hexchars[] = "0123456789abcdef";
	int offset = 0;
	unsigned long i;
	unsigned long j;
	unsigned long ret;

	unsigned long before = (position % 16);
	unsigned long after = (before+size >= 16) ? 0 : 16 - (before+size);

	//printf("============================ enter %s \n", __func__);
	//printf("data:%p size:%zu position:0x%x before:%zu after:%zu\n", data, size, position, before, after);

	for (i = 0; i < before; i++) {
		buf[offset++] = ' ';
		buf[offset++] = ' ';
		buf[offset++] = ' ';
		if (i == 7)
			buf[offset++] = ' ';
	}
	for (j = 0; j < 16 - after - before; j++) {
		uint8_t d = ((uint8_t *)data)[j];
		buf[offset++] = hexchars[(d & 0xf0) >> 4];
		buf[offset++] = hexchars[(d & 0x0f)];
		if (i+j != 15)
			buf[offset++] = ' ';
		if (i+j == 7)
			buf[offset++] = ' ';
	}
	ret = 16 - after - before;
	j += i;
	for (i = 0; i < after; i++) {
		buf[offset++] = ' ';
		buf[offset++] = ' ';
		if (i+j != 15)
			buf[offset++] = ' ';
		if (i+j == 7)
			buf[offset++] = ' ';
	}
	buf[offset] = '\0';
	//printf("============================ leave %s returning %zd\n", __func__, ret);
	return ret;
}

static inline void UNUSED
prepare_text(void *data, size_t size, char *buf, int position)
{
	int offset = 0;
	unsigned long i;
	unsigned long j;

	unsigned long before = position % 16;
	unsigned long after = (before+size > 16) ? 0 : 16 - (before+size);

	//printf("============================ enter %s \n", __func__);
	//printf("data:%p before:%zu after:%zu\n", data, before, after);

	if (size == 0) {
		buf[0] = '\0';
		return;
	}
	for (i = 0; i < before; i++)
		buf[offset++] = ' ';
	buf[offset++] = '|';
	for (j = 0; j < 16 - after - before; j++) {
		if (isprint(((uint8_t *)data)[j]))
			buf[offset++] = ((uint8_t *)data)[j];
		else
			buf[offset++] = '.';
	}
	buf[offset++] = size > 0 ? '|' : ' ';
	buf[offset] = '\0';
}

/*
 * variadic fhexdump formatted
 * think of it as: fprintf(f, %s%s\n", vformat(fmt, ap), hexdump(data,size));
 */
static inline void UNUSED
vfhexdumpf(FILE *f, const char * const fmt, uint8_t *data, unsigned long size, size_t at, va_list ap)
{
	unsigned long display_offset = at;
	unsigned long offset = 0;
	//debug("data:%p size:%zd at:%zd\n", data, size, display_offset);

	while (offset < size) {
		char hexbuf[49];
		char txtbuf[19];
		unsigned long sz;

		sz = prepare_hex(data+offset, size-offset, hexbuf,
				 (unsigned long)data+offset);
		if (sz == 0)
			return;

		prepare_text(data+offset, size-offset, txtbuf,
			     (unsigned long)data+offset);
		vfprintf(f, fmt, ap);
		fprintf(f, "%08lx  %s  %s\n", display_offset, hexbuf, txtbuf);

		display_offset += sz;
		offset += sz;
	}
	fflush(f);
}

/*
 * fhexdump formatted
 * think of it as: fprintf(f, %s%s\n", format(fmt, ...), hexdump(data,size));
 */
static inline void UNUSED
fhexdumpf(FILE *f, const char * const fmt, uint8_t *data, unsigned long size, size_t at, ...)
{
	va_list ap;

	va_start(ap, at);
	vfhexdumpf(f, fmt, data, size, at, ap);
	va_end(ap);
}

static inline void UNUSED
hexdump(uint8_t *data, unsigned long size)
{
	fhexdumpf(stdout, "", data, size, (intptr_t)data);
}

static inline void UNUSED
hexdumpat(uint8_t *data, unsigned long size, size_t at)
{
	//debug("at:%08lx\n", at);
	fhexdumpf(stdout, "", data, size, at);
}

#endif /* STATIC_HEXDUMP_H */

// vim:fenc=utf-8:tw=75:noet
