#ifndef __STRING_H
#define __STRING_H

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef STRING_INIT_BUF
#define STRING_INIT_BUF         16
#endif

typedef struct {

    size_t size;
    size_t maxbuf;

} string_metadata_t;

typedef char* string;

string new_string ();
string new_string_2 (const char *);

void free_string (string s);

size_t string_length (string s);
int string_back (string s);

string string_push_back (string s, char c);

string string_pop_back (string s);

string string_append_back (string str, const char* a);
string new_substr (const char *begin, const char *end);

#endif
