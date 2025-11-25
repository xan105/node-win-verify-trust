#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

using namespace std;
#include <iostream>

std::wstring stringToWString(const std::string& s);
int size_tToInt(size_t val);
std::string wstringToString(std::wstring wstring);
LPWSTR allocateAndCopyWideString(LPCWSTR inputString);