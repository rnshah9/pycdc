#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "pyc_string.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();

    PycString pycString;
    pycString.startsWith(str);

    return 0;
}