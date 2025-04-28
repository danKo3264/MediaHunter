#include "metadata_checker.h"
#include "report_generator.h"
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <fstream>

namespace fs = std::filesystem;

// Показать метаданные и вернуть их вектор строк
std::vector<std::string> MetadataChecker::showMetadata(const std::string& filePath) {
    std::vector<std::string> lines;
    std::cout << "\n========================================\n";
    std::cout << "Анализ файла: " << filePath << "\n";
    std::string cmd = "exiftool \"" + filePath + "\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "Не удалось запустить exiftool\n";
        return lines;
    }
    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe)) {
        lines.emplace_back(buf);
        std::cout << buf;
    }
    _pclose(pipe);
    std::cout << "\n========================================\n";
    return lines;
}

// Анализ одного файла
void MetadataChecker::analyzeFile(const std::string& filePath) {
    auto metadataLines = showMetadata(filePath);

    ReportGenerator report;
    report.generateSingleReport(filePath, metadataLines);
}

// Анализ всех файлов в директории
void MetadataChecker::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> allReports;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file())
            continue;

        std::string filePath = entry.path().string();
        auto metadataLines = showMetadata(filePath);
        allReports.emplace_back(filePath, metadataLines);
    }

    ReportGenerator report;
    report.generateDirectoryReport(dirPath, allReports);
}
