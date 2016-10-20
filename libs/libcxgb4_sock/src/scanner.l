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
int yydebug=0;
#define YYSTYPE char *
extern YYSTYPE libcxgb4_sock_yylval;
extern int config_line_num;
#include "parser.h"
%}

%option nounput
%option noinput

%%
^#.*\n			config_line_num++;
interface		return TOK_INTERFACE;
vlan			return TOK_VLAN;
port			return TOK_PORT;
priority		return TOK_PRIORITY;
endpoint		return TOK_ENDPOINT;
[a-zA-Z][a-zA-Z0-9:\-'.']*  libcxgb4_sock_yylval = strdup(libcxgb4_sock_yytext); return WORD;
[0-9]+			libcxgb4_sock_yylval = strdup(libcxgb4_sock_yytext); return NUMBER;
\{			return OBRACE;
\}			return EBRACE;
\=			return EQUAL;
\n			config_line_num++;
[ \t]+			/* ignore whitespace */
. 			return libcxgb4_sock_yytext[0];
%%
