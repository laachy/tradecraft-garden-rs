
#include <stdint.h>
#include <stddef.h>

/* Basic Win32 scalar types (LLP64 model) */
typedef uint32_t DWORD;
typedef int32_t  BOOL;
typedef uint32_t UINT;
typedef void    *LPVOID;
typedef void    *HANDLE;
typedef void    *HINSTANCE;
typedef void    *HMODULE;

typedef const char *LPCSTR;

/* Calling convention – we only need the macro to exist */
#ifndef WINAPI
#  define WINAPI
#endif

#ifndef APIENTRY
#  define APIENTRY WINAPI
#endif

#ifndef CALLBACK
#  define CALLBACK WINAPI
#endif

/* FARPROC – generic function pointer */
typedef void (*FARPROC)(void);

/* Opaque PE structs – we only ever use pointers to them in tcg.h */
typedef struct _IMAGE_DOS_HEADER      IMAGE_DOS_HEADER;
typedef struct _IMAGE_NT_HEADERS      IMAGE_NT_HEADERS;
typedef struct _IMAGE_OPTIONAL_HEADER IMAGE_OPTIONAL_HEADER;
typedef struct _IMAGE_DATA_DIRECTORY  IMAGE_DATA_DIRECTORY;

/* Prototypes so __typeof__(LoadLibraryA/GetProcAddress) works */
HMODULE WINAPI LoadLibraryA(LPCSTR lpLibFileName);
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
