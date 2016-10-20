/*
 * Copyright (c) 2010-2015 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
%{
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "libcxgb4_sock.h"

extern int yylex(void);
extern void yyerror(const char *str);
int parse_err;

char interface[IFNAMSIZ];
unsigned short vlan;
unsigned char priority;
unsigned short port;
int config_line_num = 1;

#define YYSTYPE char *
extern YYSTYPE libcxgb4_sock_yytext;

void libcxgb4_sock_yyerror(const char *str)
{
        fprintf(stderr, "Error in %s line number %u token '%s': %s.\n",
		CONFIG_FILE, config_line_num, libcxgb4_sock_yytext, str);
	parse_err = 1;
}

int libcxgb4_sock_yywrap()
{
        return 1;
} 
  
%}

%token OBRACE EBRACE EQUAL WORD NUMBER 
%token TOK_ENDPOINT TOK_INTERFACE TOK_VLAN TOK_PORT TOK_PRIORITY

%%
endpoints:
	|
	endpoints endpoint
	{ 
		vlan = VLAN_ID_NA;
		interface[0] = 0;
		port = 0;
		priority = 0;
		parse_err = 0;
	}
	;
endpoint:
	TOK_ENDPOINT OBRACE endpoint_attrs EBRACE
	{ 
		add_endpoint(interface, port, vlan, priority);
	}
	;
endpoint_attrs:
	|
	endpoint_attrs attr
	;
attr:
	TOK_INTERFACE EQUAL WORD
	{
		strcpy(interface, $3);
	}
	|
	TOK_VLAN EQUAL NUMBER
	{
		vlan = atoi($3);
	}
	|
	TOK_PORT EQUAL NUMBER
	{
		port = htons(atoi($3));
	}
	|
	TOK_PRIORITY EQUAL NUMBER
	{
		priority = atoi($3);
	}
	;

%%

int parse_config_file(const char *filename)
{
	extern FILE *libcxgb4_sock_yyin;
	extern int yyparse();
	
	if (access(filename, R_OK)) {
		printf("Error: Cannot open %s\n", filename);
		return 1;
	}
	libcxgb4_sock_yyin = fopen(filename, "r");
	if (!libcxgb4_sock_yyin) {
		printf("Error: Failed to open %s\n", filename);
		return 1;
	}
	parse_err = 0;
	yyparse();
	fclose(libcxgb4_sock_yyin);
	return parse_err;
}
