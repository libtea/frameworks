
/* See LICENSE file for license and copyright information */


#ifndef LIBTEA_H
#define LIBTEA_H


/* Top-level definition to propagate to all files. This header should be included
 * in every other Libtea source file.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  
#endif


/* Just as important as the top-level GNU_SOURCE definition! */
#if defined(__linux__) || defined(LINUX) || defined(__linux)
#define LIBTEA_LINUX 1
#endif


#if defined(__ANDROID__) || defined(__android__) || defined(ANDROID)
/* We use mostly LIBTEA_LINUX functionality for Android, so define both, and use the
 * presence or absence of LIBTEA_ANDROID to distinguish between the two operating
 * systems where needed.
 */
#define LIBTEA_LINUX 1
#define LIBTEA_ANDROID 1
#endif


#define LIBTEA_SUPPORT_CACHE 1
#define LIBTEA_SUPPORT_PAGING 1
#define LIBTEA_SUPPORT_INTERRUPTS 1
#define LIBTEA_SUPPORT_SGX 0
/* Currently we only have enclave support for Intel SGX. Future work could extend this to
 * other enclave types, e.g. ARM TrustZone.
 */
#define LIBTEA_SUPPORT_ENCLAVES LIBTEA_SUPPORT_SGX