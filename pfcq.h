/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * Copyright 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#ifndef __PFCQ_H__
#define __PFCQ_H__

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#define PFCQ_STACKTRACE_SIZE	20

#define __noop					(void)0

#define inform(A, ...)			__pfcq_debug(1, A, __VA_ARGS__)
#define verbose(A, ...)			__pfcq_debug(0, A, __VA_ARGS__)

#ifdef MODE_DEBUG
#define debug(A, ...)			__pfcq_debug(0, A, __VA_ARGS__)
#else /* MODE_DEBUG */
#define debug(A, ...)			__noop
#endif /* MODE_DEBUG */

#define warning(A)				__pfcq_warning(A, errno, __FILE__, __LINE__, 1)
#define panic(A)				__pfcq_panic(A, errno, __FILE__, __LINE__)

#define pfcq_zero(A, B)			memset(A, 0, B)
#define pfcq_free(A)			__pfcq_free((void**)&(A))

#ifdef __GNUC__
#define likely(x)				__builtin_expect(!!(x), 1)
#define unlikely(x)				__builtin_expect(!!(x), 0)
#else /* __GNUC__ */
#define likely(x)				(x)
#define unlikely(x)				(x)
#endif /* __GNUC__ */

#define CHMOD_755					(S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define CHMOD_644					(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define GLFS_DEFAULT_PORT			24007
#define GLFS_DEFAULT_PROTOCOL		"tcp"
#define GLFS_DEFAULT_VERBOSITY		7
#define DEV_NULL					((const char*)"/dev/null")
#define DEV_STDERR					((const char*)"/dev/stderr")
#define DENTRY_BUFFER_SIZE			512
#define IO_CHUNK_SIZE				(4 * 1024 * 1024)
#define NET_CHUNK_SIZE				16384
#define EPOLL_MAXEVENTS				32

typedef struct pfcq_size_unit
{
	uint64_t base;
	const char* unit;
} pfcq_size_unit_t;

void __pfcq_debug(int _direct, const char* _format, ...) __attribute__((format(printf, 2, 3), nonnull(2)));
void __pfcq_warning(const char* _message, const int _errno, const char* _file, int _line, int _direct) __attribute__((nonnull(1, 3)));
void __pfcq_panic(const char* _message, const int _errno, const char* _file, int _line) __attribute__((noreturn, nonnull(1, 3)));
void pfcq_debug_init(int _verbose, int _debug, int _syslog);
void pfcq_debug_done(void);

void* pfcq_alloc(size_t _size) __attribute__((malloc, warn_unused_result));
void* pfcq_realloc(void* _old_pointer, size_t _new_size) __attribute__((malloc, nonnull(1), warn_unused_result));
void __pfcq_free(void** _pointer) __attribute__((nonnull(1)));

int pfcq_isnumber(const char* _string) __attribute__((nonnull(1), warn_unused_result));
char* pfcq_strdup(const char* _string) __attribute__((nonnull(1), warn_unused_result));
char* pfcq_mstring(const char* _format, ...) __attribute__((format(printf, 1, 2), nonnull(1), warn_unused_result));
char* pfcq_cstring(char* _left, const char* _right) __attribute__((nonnull(1, 2)));
char* pfcq_bstring(const char* _buffer, size_t _buffer_size) __attribute__((nonnull(1), warn_unused_result));
uint64_t pfcq_mbytes(const char* _human_readable) __attribute__((nonnull(1)));

int pfcq_isopened(const char* _path) __attribute__((nonnull(1), warn_unused_result));
char* pfcq_get_file_path_from_fd(int _fd, char* _buffer, size_t _buffer_size) __attribute__((nonnull(2), warn_unused_result));

static inline uint64_t __pfcq_timespec_diff_ns(struct timespec _timestamp1, struct timespec _timestamp2) __attribute__((always_inline));
static inline uint64_t __pfcq_timespec_to_ns(struct timespec _timestamp) __attribute__((always_inline));

static inline uint64_t __pfcq_timespec_diff_ns(struct timespec _timestamp1, struct timespec _timestamp2)
{
	uint64_t ns1 = __pfcq_timespec_to_ns(_timestamp1);
	uint64_t ns2 = __pfcq_timespec_to_ns(_timestamp2);
	return ns2 - ns1;
}

static inline uint64_t __pfcq_timespec_to_ns(struct timespec _timestamp)
{
	return _timestamp.tv_sec * 1000000000ULL + _timestamp.tv_nsec;
}

#endif /* __PFCQ_H__ */

