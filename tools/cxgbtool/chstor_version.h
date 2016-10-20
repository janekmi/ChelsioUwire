/******************************************************************************
 *
 * Copyright (c) Chelsio Communications.  All rights reserved.
 *
 *   THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
 *   KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
 *   PURPOSE.
 *
 * Module Name:
 *
 *    chstor_version.h
 *
 * Abstract:
 *
 *    chstor_version.h -  contains the version information.
 *
 * Environment:
 *
 *    User mode
 *
 * Revision History:
 *
 *	Gokul TV - 04-May-10 -	Creation
 *
 *****************************************************************************/

#ifndef __CSIO_VERSION_H__
#define __CSIO_VERSION_H__

#define CSIO_COPYRIGHT_INFORMATION          "Copyright \251 2011 Chelsio Communications"
#define CSIO_COPYRIGHT_INFORMATION_ASCII    "Copyright (C) 2011 Chelsio Communications"

#define CHELSIO_COMMUNICATIONS		    "Chelsio Communications"

/*
 * File version information.
 *
 */

#define CHSTORUTIL_MAJOR_VERSION		1
#define CHSTORUTIL_MINOR_VERSION		2
#define CHSTORUTIL_REVISION_NUMBER		0
#define CHSTORUTIL_BUILD_NUMBER			12

#define CHSTORUTIL_VERSION_ASCII_STRING2(w, x, y, z)    #w "." #x "." #y "." #z

#define CHSTORUTIL_VERSION_ASCII_STRING1(w, x, y, z)    \
			CHSTORUTIL_VERSION_ASCII_STRING2(w, x, y, z)

#define CHSTORUTIL_VERSION_ASCII                        		\
	CHSTORUTIL_VERSION_ASCII_STRING1(CHSTORUTIL_MAJOR_VERSION,  	\
					CHSTORUTIL_MINOR_VERSION,  	\
					CHSTORUTIL_REVISION_NUMBER,	\
					CHSTORUTIL_BUILD_NUMBER)

#define CHSTORUTIL_VERSION_NUMBER	CHSTORUTIL_MAJOR_VERSION,  \
					CHSTORUTIL_MINOR_VERSION,  \
					CHSTORUTIL_REVISION_NUMBER,\
					CHSTORUTIL_BUILD_NUMBER

#endif /* __CSIO_VERSION_H__ */
