#include "ds/string.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void *string_to_ptr (string s) {
    return ((void *) s) - sizeof (string_metadata_t);
}
string ptr_to_string (void *ptr) {
    return (string) (ptr + sizeof (string_metadata_t));
}

string new_string () {
    assert (STRING_INIT_BUF >= 2);
    size_t totsize = sizeof (string_metadata_t) + STRING_INIT_BUF * sizeof (char);
    void *ptr = malloc (totsize);
    if (ptr == NULL) {
        fprintf (stderr, "Unable to memory alloc string.\n");
        exit (1);
    }
    ((string_metadata_t *)ptr)->size = 0;
    ((string_metadata_t *)ptr)->maxbuf = STRING_INIT_BUF;
    string s = ptr_to_string (ptr);
    s[0] = 0;
    return s;
}

void free_string (string s) {
    void *ptr = string_to_ptr(s);
    free (ptr);
}

string preserve_buf (string s, size_t size) {
    string_metadata_t *ptr = (string_metadata_t *) string_to_ptr(s);
    if (size >= ptr->maxbuf) {
        (ptr->maxbuf) <<= 1;
        ptr = (string_metadata_t *)realloc (ptr, sizeof (string_metadata_t) + (ptr->maxbuf) * sizeof (char));
        if (ptr == NULL) {
            fprintf (stderr, "Unable to realloc string.\n");
            exit (1);
        }
        return ptr_to_string (ptr);
    }
    return s;
}
void inc_size (string s) {
    string_metadata_t *ptr = (string_metadata_t *) string_to_ptr (s);
    ++ (ptr->size);
}
void dec_size (string s) {
    string_metadata_t *ptr = (string_metadata_t *) string_to_ptr (s);
    -- (ptr->size);
}

size_t string_length (string s) {
    return ((string_metadata_t *)string_to_ptr (s))-> size;
}

string string_push_back (string s, char c) {
    if (s == NULL) {
        s = new_string ();
    }
    size_t length = string_length (s);
    s = preserve_buf(s, length + 3);
    s[length] = c;
    s[length + 1] = 0;
    inc_size (s);
    return s;
}
string string_pop_back (string s) {
    size_t length = string_length (s);
    if (length == 0) {
        fprintf (stderr, "Can not pop back an empty string.\n");
        exit (64);
    }
    s[--length] = 0;
    dec_size (s);
    return s;
}

string string_append_back (string str, const char *a) {
    if (str == NULL) {
        return new_string_2(a);
    }
    int len = strlen (a);
    for (int i = 0; i < len; ++i)
        str = string_push_back (str, a[i]);
    return str;
}

string new_substr (const char *begin, const char *end) {
    string s = new_string ();
    for (; begin != end; ++begin) {
        s = string_push_back (s, *begin);
    }
    return s;
}

string new_string_2 (const char *str)
{
    return new_substr (str, str + strlen (str));
}

int string_back (string s)
{
    size_t len = string_length (s);
    if (len == 0) {
        fprintf (stderr, "Yar: Error: string back called when s is empty!\n");
        return -1;
    }
    return s[len - 1];
}

