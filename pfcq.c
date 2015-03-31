/* vim: set tabstop=4:softtabstop=4:shiftwidth=4:noexpandtab */

/*
 * Copyright 2015 Lanet Network
 * Programmed by Oleksandr Natalenko <o.natalenko@lanet.ua>
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#include <ctype.h>
#include <errno.h>
#include <execinfo.h>
#include <pfcq.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>

#define STACKITEM_PREFIX_SYSLOG	"%ju) %s\n"
#define STACKITEM_PREFIX_STDERR	"\t"STACKITEM_PREFIX_SYSLOG
#define WARNING_SUFFIX_SYSLOG	"Warning #%d"
#define WARNING_SUFFIX_STDERR	WARNING_SUFFIX_SYSLOG", "
#define WARNING_UNIQ_LENGTH		4096

static int pfcq_be_verbose;
static int pfcq_do_debug;
static int pfcq_warnings_count;
static int pfcq_use_syslog;
static pthread_mutex_t pfcq_warning_ordering_lock;
static char pfcq_warning_uniq[WARNING_UNIQ_LENGTH];
static struct timespec pfcq_uniq_time;

void __pfcq_debug(int _direct, const char* _format, ...)
{
	va_list arguments;

	va_start(arguments, _format);
	if (_direct || pfcq_be_verbose || pfcq_do_debug)
	{
		if (pfcq_use_syslog)
			vsyslog(LOG_DEBUG, _format, arguments);
		else
			vfprintf(stderr, _format, arguments);
	}
	va_end(arguments);

	return;
}

static void show_stacktrace(void)
{
	void* buffer[PFCQ_STACKTRACE_SIZE];
	size_t buffer_size = 0;
	char** symbols = NULL;

	pfcq_zero(buffer, PFCQ_STACKTRACE_SIZE * sizeof(void*));

	buffer_size = backtrace(buffer, PFCQ_STACKTRACE_SIZE);
	symbols = backtrace_symbols(buffer, buffer_size);

	__pfcq_debug(1, "Stacktrace:\n");
	for (size_t i = 0; i < buffer_size; i++)
		__pfcq_debug(1, pfcq_use_syslog ? STACKITEM_PREFIX_SYSLOG : STACKITEM_PREFIX_STDERR, i, symbols[i]);

	free(symbols);

	return;
}

void __pfcq_warning(const char* _message, const int _errno, const char* _file, int _line, int _direct)
{
	char current_uniq[WARNING_UNIQ_LENGTH];
	struct timespec current_time;
	int limit = 0;
	uint64_t time_diff;

	if (unlikely(pthread_mutex_lock(&pfcq_warning_ordering_lock)))
		exit(EX_SOFTWARE);
	if (unlikely(clock_gettime(CLOCK_MONOTONIC, &current_time) == -1))
		exit(EX_SOFTWARE);
	time_diff = __pfcq_timespec_diff_ns(current_time, pfcq_uniq_time);
	pfcq_zero(current_uniq, WARNING_UNIQ_LENGTH);
	snprintf(current_uniq, WARNING_UNIQ_LENGTH, "%s%d%s%d%d", _message, _errno, _file, _line, _direct);
	if (likely(strcmp(current_uniq, pfcq_warning_uniq) == 0))
	{
		if (likely(time_diff < 5000000000ULL))
		{
			limit = 1;
		} else
		{
			memcpy(&pfcq_uniq_time, &current_time, sizeof(struct timespec));
		}
	} else
	{
		memcpy(&pfcq_uniq_time, &current_time, sizeof(struct timespec));
		pfcq_zero(pfcq_warning_uniq, WARNING_UNIQ_LENGTH);
		strncpy(pfcq_warning_uniq, current_uniq, WARNING_UNIQ_LENGTH);
	}
	if (likely(_direct))
	{
		pfcq_warnings_count++;
		if (unlikely(!limit))
			__pfcq_debug(1, pfcq_use_syslog ? WARNING_SUFFIX_SYSLOG : WARNING_SUFFIX_STDERR, pfcq_warnings_count);
	}
	if (unlikely(!limit))
	{
		__pfcq_debug(1, "File=%s, line=%d\n", _file, _line);
		__pfcq_debug(1, "%s: %s\n", _message, strerror(_errno));
		show_stacktrace();
	}
	if (unlikely(pthread_mutex_unlock(&pfcq_warning_ordering_lock)))
		exit(EX_SOFTWARE);

	return;
}

void __pfcq_panic(const char* _message, const int _errno, const char* _file, int _line)
{
	__pfcq_warning(_message, _errno, _file, _line, 0);
	exit(EX_SOFTWARE);
}

void pfcq_debug_init(int _verbose, int _debug, int _syslog)
{
	pfcq_be_verbose = _verbose;
	pfcq_do_debug = _debug;
	pfcq_use_syslog = _syslog;
	pfcq_warnings_count = 0;
	pfcq_zero(pfcq_warning_uniq, WARNING_UNIQ_LENGTH);
	pfcq_zero(&pfcq_uniq_time, sizeof(struct timespec));
	if (unlikely(pthread_mutex_init(&pfcq_warning_ordering_lock, NULL)))
		panic("pthread_mutex_init");
	if (pfcq_use_syslog)
		openlog(NULL, LOG_PID, LOG_DAEMON);

	return;
}

void pfcq_debug_done(void)
{
	if (unlikely(pthread_mutex_destroy(&pfcq_warning_ordering_lock)))
		panic("pthread_mutex_init");
	if (pfcq_use_syslog)
		closelog();

	return;
}

void* pfcq_alloc(size_t _size)
{
	void* res = NULL;

	_size += sizeof(size_t);
	res = calloc(1, _size);
	if (unlikely(!res))
		panic("calloc");
	*(size_t*)res = _size;

	return ((size_t*)res) + 1;
}

void* pfcq_realloc(void* _old_pointer, size_t _new_size)
{
	void* tmp = NULL;

	_new_size += sizeof(size_t);
	_old_pointer = (void*)(((size_t*)_old_pointer) - 1);
	if (unlikely(!_old_pointer))
		panic("NULL pointer detected");

	tmp = realloc(_old_pointer, _new_size);
	if (unlikely(!tmp))
		panic("realloc");
	*(size_t*)tmp = _new_size;

	return ((size_t*)tmp) + 1;
}

void __pfcq_free(void** _pointer)
{
	if (likely(_pointer))
	{
		size_t* p = ((size_t*)(*_pointer)) - 1;
		if (likely(p))
		{
			size_t size = *p;
			pfcq_zero(p, size);
			free(p);
			*_pointer = NULL;
		}
	}
}

int pfcq_isnumber(const char* _string)
{
	while (likely(*_string))
	{
		char current_char = *_string++;
		if (unlikely(isdigit(current_char) == 0))
			return 0;
	}

	return 1;
}

char* pfcq_mstring(const char* _format, ...)
{
	va_list arguments;
	char* ret = NULL;

	va_start(arguments, _format);
	int length = vsnprintf(NULL, 0, _format, arguments);
	va_end(arguments);

	if (unlikely(length < 0))
		return ret;

	ret = pfcq_alloc(length + 1);

	va_start(arguments, _format);
	vsprintf(ret, _format, arguments);
	va_end(arguments);

	return ret;
}

char* pfcq_strdup(const char* _string)
{
	return pfcq_mstring("%s", _string);
}

char* pfcq_cstring(char* _left, const char* _right)
{
	size_t left_length = strlen(_left);
	size_t right_length = strlen(_right);

	char* ret = pfcq_realloc(_left, left_length + right_length + 1);
	memcpy(ret + left_length, _right, right_length);
	ret[left_length + right_length] = '\0';

	return ret;
}

