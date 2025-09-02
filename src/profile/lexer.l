%option noyywrap
%option yylineno
%option reentrant
%option bison-bridge
%option bison-locations

%{
#include "profile.h"
#include "profile_parser.tab.h"

#include <string.h>

#define extra ((struct scanner_extra_t *)yyextra)
%}

%%

#[^\n]*			;

[ \t]+			{
	return WHITESPACE;
}
\n			{
		return EOL;
}
\'[^']*\'		{
	yylval->str = strdup(yytext);
	return WORD;
}
\"([^"\\]|\\.)*\"	{
	yylval->str = strdup(yytext);
	return WORD;
}
([^ \t\n\\]|\\.)+	{
	yylval->str = strdup(yytext);
	return WORD;
}

%%
