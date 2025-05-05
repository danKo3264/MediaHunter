#include "metadata_checker.h"
#include "report_generator.h"
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <fstream>

namespace fs = std::filesystem;

#include "metadata_checker.h"
#include <iostream>
#include <filesystem>
#include <cstdio>

namespace fs = std::filesystem;

// ������ ������ �����: ����� + ������� ����������
std::vector<std::string> MetadataChecker::analyzeFile(const std::string& filePath) {
    std::vector<std::string> lines;
    std::cout << "========================================\n";
    std::cout << "������ �����: " << filePath << "\n";

    std::string cmd = "exiftool \"" + filePath + "\"";
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) {
        std::cerr << "�� ������� ��������� exiftool\n";
        lines.emplace_back("������ ������� exiftool");
        return lines;
    }

    char buf[1024];
    while (fgets(buf, sizeof(buf), pipe)) {
        std::string line(buf);
        lines.emplace_back(line);
        std::cout << line;
    }

    _pclose(pipe);
    std::cout << "========================================\n";
    return lines;
}

// ������ ����������: �� ������� ����� �������� analyzeFile
std::vector<std::pair<std::string, std::vector<std::string>>> MetadataChecker::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> reports;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        std::string filePath = entry.path().string();
        auto metadata = analyzeFile(filePath);  // ����� ��� �������
        reports.emplace_back(filePath, metadata);
    }

    return reports;
}