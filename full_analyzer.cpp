#include "full_analyzer.h"
#include "signature_scanner.h"
#include "metadata_checker.h"
#include "steganography_checker.h"
#include "extension_checker.h"
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

FullAnalyzer::FullAnalyzer(const std::string& rulesPath)
    : scanner_(rulesPath) {
}

std::vector<std::string> FullAnalyzer::analyzeFile(const std::string& filePath) {
    std::vector<std::string> lines;

    if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) {
        std::cerr << "Ошибка: файл не найден или недоступен: " << filePath << "\n";
        lines.push_back("Ошибка: файл не найден или недоступен.");
        return lines;
    }

    std::cout << "========================================\n";
    std::cout << "Файл: " << filePath << "\n";
    
    lines.push_back("Файл: " + filePath);

    try {
        std::cout << "========================================\n";
        std::cout << "Анализ файла: " << filePath << "\n";
        std::string threat = scanner_.analyzeFile(filePath);
        if (threat == "OK") {
            std::cout << "Результат сигнатурного анализа: угроз не обнаружено.\n";
            lines.push_back("Результат сигнатурного анализа: угроз не обнаружено.");
        }
        else {
            std::cout << "Результат сигнатурного анализа: обнаружена угроза: " << threat << "\n";
            lines.push_back("Результат сигнатурного анализа: обнаружена угроза: " + threat);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Ошибка при сигнатурном анализе файла: " << e.what() << "\n";
        lines.push_back(std::string("Ошибка при сигнатурном анализе файла: ") + e.what());
    }

    std::cout << "========================================\n";

    MetadataChecker metadataChecker;
    std::vector<std::string> metaLines = metadataChecker.analyzeFile(filePath);
    lines.insert(lines.end(), metaLines.begin(), metaLines.end());

    SteganographyChecker stegoChecker;
    std::vector<std::string> stegLines = stegoChecker.analyzeFile(filePath);
    lines.insert(lines.end(), stegLines.begin(), stegLines.end());

    ExtensionChecker extChecker;
    std::vector<std::string> extLines = extChecker.analyzeFile(filePath);
    lines.insert(lines.end(), extLines.begin(), extLines.end());
    

    return lines;
}

std::vector<std::pair<std::string, std::vector<std::string>>> FullAnalyzer::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> reports;

    if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
        std::cerr << "Ошибка: директория не найдена или недоступна: " << dirPath << "\n";
        return reports;
    }

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        std::string filePath = entry.path().string();

        auto lines = analyzeFile(filePath);
        reports.emplace_back(filePath, lines);
        std::cout << "\n";
    }

    return reports;
}
