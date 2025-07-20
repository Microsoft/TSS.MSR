/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    stdafx.h

Abstract:

    Pre-Compiled Header for PCPTool.

--*/

#pragma once

#include <new>

#include <windows.h>
#include <IntSafe.h>

#include <stdio.h>
#include <tchar.h>
#include <Strsafe.h>

#include <bcrypt.h>
#include <ncrypt.h>
#include <Cryptuiapi.h>
#include <Wincrypt.h>
#include <Winscard.h>
#include <Cryptuiapi.h>
#include <wincred.h>
#include <Objbase.h>
#include <Shlobj.h>
#include <TBS.h>
#include <wbcl.h>
#include <regex>
using namespace std;

#include "targetver.h"
#include "TpmAtt.h"
#include "InlineFn.h"
#include "pcptool.h"

