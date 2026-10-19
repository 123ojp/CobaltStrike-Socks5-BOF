#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

DECLSPEC_IMPORT int             WINAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
DECLSPEC_IMPORT int             WINAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET          WINAPI WS2_32$socket(int af, int type, int protocol);
DECLSPEC_IMPORT int             WINAPI WS2_32$bind(SOCKET s, const struct sockaddr * name, int namelen);
DECLSPEC_IMPORT int             WINAPI WS2_32$listen(SOCKET s, int backlog);
DECLSPEC_IMPORT SOCKET          WINAPI WS2_32$accept(SOCKET s, struct sockaddr * addr, int * addrlen);
DECLSPEC_IMPORT int             WINAPI WS2_32$connect(SOCKET s, const struct sockaddr * name, int namelen);
DECLSPEC_IMPORT int             WINAPI WS2_32$recv(SOCKET s, char * buf, int len, int flags);
DECLSPEC_IMPORT int             WINAPI WS2_32$send(SOCKET s, const char * buf, int len, int flags);
DECLSPEC_IMPORT int             WINAPI WS2_32$select(int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds, const struct timeval * timeout);
DECLSPEC_IMPORT int             WINAPI WS2_32$closesocket(SOCKET s);
DECLSPEC_IMPORT int             WINAPI WS2_32$shutdown(SOCKET s, int how);
DECLSPEC_IMPORT u_short         WINAPI WS2_32$htons(u_short hostshort);
DECLSPEC_IMPORT u_long          WINAPI WS2_32$htonl(u_long hostlong);
DECLSPEC_IMPORT unsigned long   WINAPI WS2_32$inet_addr(const char * cp);
DECLSPEC_IMPORT struct hostent *WINAPI WS2_32$gethostbyname(const char * name);
DECLSPEC_IMPORT int             WINAPI WS2_32$ioctlsocket(SOCKET s, long cmd, u_long * argp);
DECLSPEC_IMPORT int             WINAPI WS2_32$getsockopt(SOCKET s, int level, int optname, char * optval, int * optlen);
DECLSPEC_IMPORT int             WINAPI WS2_32$setsockopt(SOCKET s, int level, int optname, const char * optval, int optlen);
DECLSPEC_IMPORT int             WINAPI WS2_32$WSAGetLastError(void);

DECLSPEC_IMPORT HANDLE          WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID          WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL            WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT DWORD           WINAPI KERNEL32$GetTickCount(void);

DECLSPEC_IMPORT void *          __cdecl MSVCRT$memcpy(void * dst, const void * src, size_t count);
DECLSPEC_IMPORT void *          __cdecl MSVCRT$memset(void * dst, int c, size_t count);
DECLSPEC_IMPORT void *          __cdecl MSVCRT$memmove(void * dst, const void * src, size_t count);
