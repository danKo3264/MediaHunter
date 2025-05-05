#include "report_generator.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <limits>

namespace fs = std::filesystem;

ReportGenerator::ReportGenerator(bool suppressPrompt)
    : suppressPrompt_(suppressPrompt) {
}

// Запрос у пользователя подтверждения сохранения
bool ReportGenerator::askUserToSave(const std::string& description) {
    std::cout << "Сохранить " << description << "? (y/n): ";
    char response;
    std::cin >> response;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return (response == 'y' || response == 'Y');
}

// Генерация отчёта для одного файла
void ReportGenerator::generateSingleReport(const std::string& filePath, const std::vector<std::string>& reportLines) {
    if (!askUserToSave("отчёт для файла")) {
        std::cout << "Отмена сохранения отчёта.\n";
        return;
    }

    std::string outPath = filePath + "_report.txt";
    std::ofstream out(outPath);
    if (!out) {
        std::cerr << "Не удалось создать отчёт: " << outPath << "\n";
        return;
    }

    for (const auto& line : reportLines) {
        out << line << "\n";
    }
    std::cout << "Отчёт сохранён: " << outPath << "\n";
}

// Генерация общего отчёта для директории
void ReportGenerator::generateDirectoryReport(const std::string& dirPath, const std::vector<std::pair<std::string, std::vector<std::string>>>& fileReports) {
    if (!askUserToSave("общий отчёт для директории")) {
        std::cout << "Отмена сохранения отчёта.\n";
        return;
    }

    std::string outPath = (fs::path(dirPath) / "directory_report.txt").string();
    std::ofstream out(outPath);
    if (!out) {
        std::cerr << "Не удалось создать отчёт: " << outPath << "\n";
        return;
    }

    for (const auto& [filePath, lines] : fileReports) {
        out << "Файл: " << filePath << "\n";
        for (const auto& line : lines) {
            out << line << "\n";
        }
        out << "\n";
    }
    std::cout << "Общий отчёт сохранён: " << outPath << "\n";
}
