#ifndef SOCKS5_BEACON_H
#define SOCKS5_BEACON_H

#include <windows.h>

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

typedef struct {
	char * original;
	char * buffer;
	int    length;
	int    size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT int  BeaconDataInt(datap * parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap * parser, int * size);
DECLSPEC_IMPORT void BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void BeaconPrintf(int type, char * fmt, ...);

DECLSPEC_IMPORT void  BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void *BeaconGetValue(const char * key);
DECLSPEC_IMPORT void  BeaconRemoveValue(const char * key);

#endif
