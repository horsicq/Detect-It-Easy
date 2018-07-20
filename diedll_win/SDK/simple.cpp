#include <stdio.h>
#include "diedll.h"

int main(int argc, char* argv[])
{
    char szBuffer[0x4000];
    char *pszFileName="C:\\Windows\\notepad.exe";

    DIE_scanA(pszFileName,szBuffer,sizeof(szBuffer),DIE_SHOWOPTIONS+DIE_SHOWVERSION);
    printf("%s",szBuffer);

    return 0;
}

