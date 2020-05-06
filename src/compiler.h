// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * compiler.h - compiler related macros
 * Copyright Peter Jones <pjones@redhat.com>
 */

#ifndef COMPILER_H_
#define COMPILER_H_

#include <sys/cdefs.h>

/* GCC version checking borrowed from glibc. */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#  define GNUC_PREREQ(maj,min) \
	((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#  define GNUC_PREREQ(maj,min) 0
#endif

/* Does this compiler support compile-time error attributes? */
#if GNUC_PREREQ(4,3)
#  define ATTRIBUTE_ERROR(msg) \
	__attribute__ ((__error__ (msg)))
#else
#  define ATTRIBUTE_ERROR(msg) __attribute__ ((noreturn))
#endif

#if GNUC_PREREQ(4,4)
#  define GNU_PRINTF gnu_printf
#else
#  define GNU_PRINTF printf
#endif

#if GNUC_PREREQ(3,4)
#  define WARN_UNUSED_RESULT __attribute__ ((warn_unused_result))
#else
#  define WARN_UNUSED_RESULT
#endif

#if defined(__clang__) && defined(__clang_major__) && defined(__clang_minor__)
#  define CLANG_PREREQ(maj,min) \
          ((__clang_major__ > (maj)) || \
	   (__clang_major__ == (maj) && __clang_minor__ >= (min)))
#else
#  define CLANG_PREREQ(maj,min) 0
#endif

#define UNUSED __attribute__((__unused__))
#define HIDDEN __attribute__((__visibility__ ("hidden")))
#define PUBLIC __attribute__((__visibility__ ("default")))
#define DESTRUCTOR __attribute__((__destructor__))
#define CONSTRUCTOR __attribute__((__constructor__))
#define ALIAS(x) __attribute__((weak, alias (#x)))
#define NONNULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#define PRINTF(...) __attribute__((__format__(printf, __VA_ARGS__)))
#define FLATTEN __attribute__((__flatten__))
#define PACKED __attribute__((__packed__))
#if GNUC_PREREQ(10,0)
# define VERSION(sym, ver) __attribute__ ((symver (# ver)))
#else
# define VERSION(sym, ver) __asm__(".symver " # sym "," # ver)
#endif
#define NORETURN __attribute__((__noreturn__))
#define ALIGNED(n) __attribute__((__aligned__(n)))
#define CLEANUP_FUNC(x) __attribute__((__cleanup__(x)))

#define __CONCAT3(a, b, c) a ## b ## c
#define CONCATENATE(a, b) __CONCAT(a, b)
#define CAT(a, b) __CONCAT(a, b)
#define CAT3(a, b, c) __CONCAT3(a, b, c)
#define STRING(x) __STRING(x)

#define WRITE_ONCE(var, val) \
        (*((volatile typeof(val) *)(&(var))) = (val))

#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))

#define __branch_check__(x, expect, is_constant) \
	__builtin_expect(!!(x), expect)
#ifndef likely
#define likely(x) (__branch_check__(x, 1, __builtin_constant_p(x)))
#endif
#ifndef unlikely
#define unlikely(x) (__branch_check__(x, 0, __builtin_constant_p(x)))
#endif

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/* Compile time object size, -1 for unknown */
#ifndef __compiletime_object_size
# define __compiletime_object_size(obj) -1
#endif
#ifndef __compiletime_warning
# define __compiletime_warning(message)
#endif
#ifndef __compiletime_error
# define __compiletime_error(message)
#endif

#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)

#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__)

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)

#define __ALIGN_MASK(x, mask)   (((x) + (mask)) & ~(mask))
#define __ALIGN(x, a)           __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)             __ALIGN((x), (a))
#define ALIGN_DOWN(x, a)        __ALIGN((x) - ((a) - 1), (a))

#define ALIGNMENT_PADDING(value, align) ((align - (value % align)) % align)
#define ALIGN_UP(value, align) ((value) + ALIGNMENT_PADDING(value, align))

#endif /* !COMPILER_H_ */
// vim:fenc=utf-8:tw=75:noet
