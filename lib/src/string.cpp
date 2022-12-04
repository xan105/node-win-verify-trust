/*
Copyright (c) Anthony Beaumont
This source code is licensed under the MIT License
found in the LICENSE file in the root directory of this source tree.
*/

#define _UNICODE 1
#define UNICODE 1

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

using namespace std;
#include <iostream>

#include "string.h"

std::wstring stringToWString(const std::string& s)
{
    int length;
    int slength = (int)s.length() + 1;
    length = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    std::wstring buf;
    buf.resize(length);
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, const_cast<wchar_t*>(buf.c_str()), length);
    return buf;
}

int size_tToInt(size_t val) { //64bits
    return (val <= INT_MAX) ? (int)((size_t)val) : 0;
}

std::string wstringToString(std::wstring wstring) {

    std::string result;

    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstring[0], size_tToInt(wstring.size()), NULL, 0, NULL, NULL);
    result = std::string(size, 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, &wstring[0], size_tToInt(wstring.size()), &result[0], size, NULL, NULL);

    return result;
}

LPWSTR allocateAndCopyWideString(LPCWSTR inputString)
{
    LPWSTR outputString = NULL;

    outputString = (LPWSTR)LocalAlloc(LPTR,
        (wcslen(inputString) + 1) * sizeof(WCHAR));
    if (outputString != NULL)
    {
        lstrcpyW(outputString, inputString);
    }
    return outputString;
}