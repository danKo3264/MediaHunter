#include "signature_scanner.h"
#include <iostream>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

SignatureScanner::SignatureScanner(const std::string& rulesPath)
    : rules_(nullptr)
{
    if (yr_initialize() != ERROR_SUCCESS) {
        throw std::runtime_error("YARA инициализация завершилась с ошибкой");
    }

    if (!fs::exists(rulesPath)) {
        yr_finalize();
        throw std::runtime_error("Файл правил не найден: " + rulesPath);
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        throw std::runtime_error("Не удалось создать компилятор YARA.");
    }

    FILE* ruleFile = nullptr;
    if (fopen_s(&ruleFile, rulesPath.c_str(), "r") != 0 || !ruleFile) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        throw std::runtime_error("Не удалось открыть файл правил: " + rulesPath);
    }

    int errors = yr_compiler_add_file(compiler, ruleFile, nullptr, rulesPath.c_str());
    fclose(ruleFile);

    if (errors > 0) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        throw std::runtime_error("Ошибки при компиляции правил YARA: " + rulesPath);
    }

    if (yr_compiler_get_rules(compiler, &rules_) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        throw std::runtime_error("Не удалось получить правила из компилятора.");
    }

    yr_compiler_destroy(compiler);
}

SignatureScanner::~SignatureScanner() {
    if (rules_) {
        yr_rules_destroy(rules_);
    }
    yr_finalize();
}

std::string SignatureScanner::analyzeFile(const std::string& filePath) {
    std::string matchedRule;
    int res = yr_rules_scan_file(
        rules_,
        filePath.c_str(),
        0,
        yaraCallback,
        &matchedRule,
        0
    );

    if (res != ERROR_SUCCESS && res != ERROR_SCAN_TIMEOUT) {
        std::cerr << "YARA ошибка " << res << " при сканировании " << filePath << std::endl;
    }

    return matchedRule.empty() ? "OK" : matchedRule;
}

int SignatureScanner::yaraCallback(
    YR_SCAN_CONTEXT* ctx,
    int message,
    void* message_data,
    void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = reinterpret_cast<YR_RULE*>(message_data);
        std::string* matchedRule = static_cast<std::string*>(user_data);
        *matchedRule = rule->identifier;
        return CALLBACK_ABORT;
    }
    return CALLBACK_CONTINUE;
}

