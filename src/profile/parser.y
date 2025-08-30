%parse-param { struct config *cfg }
%lex-param { struct config *cfg }

%{
#include "config.h"
#include "config_parser.tab.h"
#include <stdio.h>
#include <stdlib.h>

void
yyerror(struct config *cfg, const char *s);
int
yylex(struct config *cfg);
%}

%union {
	char *str;
	struct kv_pair *kv;
	struct section *sec;
}

%token<str> SECTION_HEADER KEY VALUE

%type<kv> kv_pair kv_pair_list
%type<sec> section section_list

%%

file: kv_pair_list section_list
	{
		cfg->pairs = $1;
		cfg->sections = $2;
	}
	;

kv_pair: KEY VALUE 
	{
		$$ = kv_pair__create($1, $2);
	}
	;

kv_pair_list: /* empty */
	{
		$$ = NULL;
	}
	| kv_pair kv_pair_list
	{
		$1->next = $2;
		$$ = $1;
	}
	;

section: SECTION_HEADER kv_pair_list
	{
		$$ = section__create($1, $2);
	}
	;

section_list: /* empty */
	{
		$$ = NULL;
	}
	| section section_list
	{
		$1->next = $2;
		$$ = $1;
	}
	;

%%

void
yyerror(struct config *cfg, const char *s)
{
	fprintf(stderr, "Parse error: %s\n", s);
}
