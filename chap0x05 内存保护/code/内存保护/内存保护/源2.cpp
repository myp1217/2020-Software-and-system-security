#include <windows.h>
#include<stdio.h>
int main()
{
	SYSTEM_INFO sSysInfo;
	GetSystemInfo(&sSysInfo);
	DWORD dwPageSize = sSysInfo.dwPageSize;
	//分配内存，标记为提交、可读可写
	LPVOID lpvBase = VirtualAlloc((LPVOID)0x30000000, dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpvBase == NULL)
		return 0;

	LPTSTR ustr;
	ustr = (LPTSTR)lpvBase;
	for (DWORD i = 0; i < dwPageSize; i++)
	{
		ustr[i] = '2';
		printf("%c", ustr[i]);
	}
	return 1;
}