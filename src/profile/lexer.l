%option noyywrap
%option yylineno
%option bison-bridge
%option never-interactive

%{
#include "config.h"
#include "config_parser.tab.h"
#include "util.h"

#include <string.h>
#include <stdlib.h>
%}

%x EQ_STATE VL_STATE 

%%

<*>"#"[^\n]*	;

"["[a-zA-Z0-9_\-]+"]" {
	int len = yyleng - 2;
	yylval->str = (char *)malloc(len + 1);
	if (!yylval->str) {
		PERROR("malloc");
		exit(EXIT_FAILURE);
	}
	strncpy(yylval->str, yytext + 1, len);
	yylval->str[len] = '\0';	
	return SECTION_HEADER;
}

[a-zA-Z0-9_\-]+ {
	yylval->str = strdup(yytext);
	if (!yylval->str) {
		PERROR("strdup");
		exit(EXIT_FAILURE);
	}
	BEGIN(EQ_STATE);
	return KEY;
}

<EQ_STATE>[ \t]*"=" {
	BEGIN(VL_STATE);
}

<VL_STATE>[^\n]* {
	yylval->str = strdup(yytext);
	if (!yylval->str) {
		PERROR("strdup");
		exit(EXIT_FAILURE);
	}
	BEGIN(INITIAL);
	return VALUE;
}

\n	;

%%
