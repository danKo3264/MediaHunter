#pragma once
#ifndef SIGNATURE_SCANNER_H
#define SIGNATURE_SCANNER_H

#include <string>
#include <stdexcept>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#undef byte
#endif

#include <yara.h>

class SignatureScanner {
public:
    explicit SignatureScanner(const std::string& rulesPath = "rules.yar");
    ~SignatureScanner();
    std::string analyzeFile(const std::string& filePath);

private:
    YR_RULES* rules_;
    static int yaraCallback(YR_SCAN_CONTEXT* ctx,
        int message,
        void* message_data,
        void* user_data);
};

#endif // SIGNATURE_SCANNER_H
