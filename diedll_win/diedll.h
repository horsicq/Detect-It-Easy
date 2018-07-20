#ifndef DIEDLL_H
#define DIEDLL_H

#include <windows.h>

// flags
#define DIE_SHOWERRORS              0x00000001
#define DIE_SHOWOPTIONS             0x00000002
#define DIE_SHOWVERSION             0x00000004
#define DIE_SHOWENTROPY             0x00000008
#define DIE_SINGLELINEOUTPUT        0x00000010
#define DIE_SHOWFILEFORMATONCE      0x00000020
#define DIE_DEEPSCAN                0x00000080

#ifdef __cplusplus
extern "C" {
#endif

int  __declspec(dllexport) __stdcall DIE_scanA(char *pszFileName,char *pszOutBuffer,int nOutBufferSize,unsigned int nFlags);
int  __declspec(dllexport) __stdcall DIE_scanW(wchar_t *pwszFileName,char *pszOutBuffer,int nOutBufferSize,unsigned int nFlags);
int  __declspec(dllexport) __stdcall DIE_scanExA(char *pszFileName,char *pszOutBuffer,int nOutBufferSize,unsigned int nFlags,char *pszDataBase);
int  __declspec(dllexport) __stdcall DIE_scanExW(wchar_t *pwszFileName,char *pszOutBuffer,int nOutBufferSize,unsigned int nFlags,wchar_t *pwszDataBase);
PCHAR __declspec(dllexport) __stdcall DIE_versionA(void);
PWCHAR __declspec(dllexport) __stdcall DIE_versionW(void);


#ifdef UNICODE
#define DIE_scan DIE_scanW
#define DIE_scanEx DIE_scanExW
#define DIE_version DIE_versionW
#else
#define DIE_scan DIE_scanA
#define DIE_scanEx DIE_scanExA
#define DIE_version DIE_versionA
#endif

#ifdef __cplusplus
}
#endif

#endif // DIEDLL_H
