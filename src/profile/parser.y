%define api.pure
%locations

%lex-param{void *scanner}

%parse-param{void *scanner}
%parse-param{struct profile_t *profile}

%{
#include "profile.h"
#include "profile_parser.tab.h"
#include "profile_lexer.h"
#include <stdio.h>
#include <stdlib.h>

int yylex(YYSTYPE *, YYLTYPE *, yyscan_t);
void yyerror(YYLTYPE *loc, yyscan_t scanner,
	     struct profile_t *profile, const char *error_msg);
%}

%union{
	char *str;
	struct string_list_t *slist;
	struct profile_command_t *cmd;
	struct profile_command_list_t *cmd_list;
}

%token WHITESPACE EOL
%token<str> WORD
%type<str> string
%type<slist> string_list
%type<cmd> command
%type<cmd_list> command_list

%%

profile:
	/* empty */
	{
		profile->cmd_list = NULL;
	}
	| command_list
	{
		profile->cmd_list = $1;	 // pass to yyparse
	};

command_list: command
	{
		struct profile_command_list_t *cmd_list =
			profile_command_list_t__create();
		profile_command_list_t__add_command(cmd_list, $1);
		$$ = cmd_list;
	}
	| command_list command_sep command
	{
		struct profile_command_list_t *cmd_list = $1;
		profile_command_list_t__add_command(cmd_list, $3);
		$$ = cmd_list;
	}
	| command_list command_sep
	{
		$$ = $1;
	}
	| command_sep command_list
	{
		$$ = $2;
	};

command_sep : EOL | WHITESPACE command_sep | command_sep WHITESPACE;

command : string_list
	{
		$$ = profile_command_t__create(profile->filename, @1, $1);
	};

string_list : string
	{
		struct string_list_t *cmd = string_list_t__create();
		string_list_t__add_arg(cmd, $1);
		$$ = cmd;
	}
	| string_list WHITESPACE
	{
		$$ = $1;
	}
	| WHITESPACE string_list
	{
		$$ = $2;
	}
	| string_list WHITESPACE string
	{
		struct string_list_t *cmd = $1;
		string_list_t__add_arg(cmd, $3);
		$$ = cmd;
	};

	string : WORD
	{
		$$ = $1;
	}
	| string WORD
	{
		char *res;
		asprintf(&res, "%s%s", $1, $2);
		free($1);
		free($2);
		$$ = res;
	};

%%

void
yyerror(YYLTYPE *loc,
	yyscan_t scanner,
	struct profile_t *profile,
	const char *error_msg)
{
	fprintf(stderr, "file %s, line %d, column %d: %s\n",
		profile->filename,
		loc->first_line,
		loc->first_column,
		error_msg);
}
