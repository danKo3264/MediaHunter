#if defined(_WIN32)
#  define NOMINMAX
#endif
#undef max
#undef min

#include <iostream>
#include <string>
#include <filesystem>
#include <limits>
#include <vector>
#include <utility>

#include "pdf_analyzer.h"
#include "file_reader.h"
#include "report_generator.h"
#include "signature_scanner.h"
#include "metadata_checker.h"
#include "steganography_checker.h"
#include "extension_checker.h"
#include "full_analyzer.h"

using namespace std;
namespace fs = std::filesystem;

// Очистка консоли
void clearConsole() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// Главное меню
void showMenu() {
    std::cout << "=== MediaHunter ===\n"
        << "Выберите тип анализа:\n"
        << "1) Анализ фото/видео файлов\n"
        << "2) Анализ метаданных файла\n"
        << "3) Поиск стеганографических встраиваний\n"
        << "4) Проверка скрытых расширений файлов\n"
        << "5) Анализ PDF-файлов\n"
        << "6) Общий анализ\n"
        << "0) Выход\n"
        << "Введите номер пункта: ";
}

// Меню выбора файла или директории
void showFileMenu() {
    std::cout << "Выберите режим работы:\n"
        << "1) Анализ файла\n"
        << "2) Анализ директории с файлами\n"
        << "0) Назад\n"
        << "Введите номер пункта: ";
}

// Проверка корректности пути
bool isValidPath(const string& path, bool isFile) {
    try {
        return isFile ? fs::is_regular_file(path) : fs::is_directory(path);
    }
    catch (...) {
        return false;
    }
}

int main() {
    setlocale(LC_ALL, "Russian");

    while (true) {
        clearConsole();
        showMenu();

        int choice;
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            std::cout << "Ошибка: введите число!\n";
            cin.get();
            continue;
        }
        if (choice == 0) break;
        if (choice < 1 || choice > 6) {
            std::cout << "Ошибка: выберите корректный пункт.\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cin.get();
            continue;
        }

        clearConsole();
        showFileMenu();

        int fileChoice;
        if (!(cin >> fileChoice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            std::cout << "Ошибка: введите число!\n";
            cin.get();
            continue;
        }
        if (fileChoice == 0) continue;
        if (fileChoice < 1 || fileChoice > 2) {
            std::cout << "Ошибка: выберите корректный пункт.\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cin.get();
            continue;
        }

        std::cout << "Введите путь к "
            << (fileChoice == 1 ? "файлу" : "директории")
            << ": ";
        string path;
        cin >> ws;
        getline(cin, path);

        if (!isValidPath(path, fileChoice == 1)) {
            std::cout << "Ошибка: путь недействителен!\n";
            cin.get();
            continue;
        }

        std::cout << "Запуск анализа...\n\n";

        switch (choice) {
        case 1: {  // Анализ фото/видео (сигнатурный сканер YARA)
            try {
                SignatureScanner scanner("rules.yar");

                if (fileChoice == 1) {
                    std::string threat = scanner.analyzeFile(path);
                    std::cout << "========================================\n";
                    std::cout << "Анализ файла: " << path << "\n\n";
                    if (threat == "OK") {
                        std::cout << "Результат: Угроз не обнаружено\n";
                    }
                    else {
                        std::cout << "Результат: Обнаружена угроза " << threat << "\n";
                    }
                    std::cout << "========================================\n\n";

                    // Сохраняем результат в отчёт
                    ReportGenerator report;
                    vector<string> lines;
                    if (threat == "OK") {
                        lines.push_back("Угроз не обнаружено");
                    }
                    else {
                        lines.push_back("Обнаружена угроза " + threat);
                    }
                    report.generateSingleReport(path, lines);
                }
                else {
                    vector<pair<string, vector<string>>> allReports;
                    for (const auto& entry : fs::directory_iterator(path)) {
                        if (!entry.is_regular_file()) continue;
                        string filePath = entry.path().string();
                        std::string threat = scanner.analyzeFile(filePath);
                        std::cout << "========================================\n";
                        std::cout << "Анализ файла: " << filePath << "\n\n";
                        if (threat == "OK") {
                            std::cout << "Результат: Угроз не обнаружено\n";
                        }
                        else {
                            std::cout << "Результат: Обнаружена угроза " << threat << "\n";
                        }
                        std::cout << "========================================\n";

                        vector<string> lines;
                        if (threat == "OK") {
                            lines.push_back("Угроз не обнаружено");
                        }
                        else {
                            lines.push_back("Обнаружена угроза " + threat);
                        }
                        allReports.emplace_back(filePath, lines);
                    }
                    std::cout << "\n";
                    ReportGenerator report;
                    report.generateDirectoryReport(path, allReports);
                }
            }
            catch (const std::runtime_error& ex) {
                cerr << "Ошибка сканирования: " << ex.what() << "\n";
            }
            break;
        }

        case 2: {  // Анализ метаданных
            MetadataChecker checker;
            if (fileChoice == 1) {
                auto result = checker.analyzeFile(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateSingleReport(path, result);
            }
            else {
                MetadataChecker checker;
                auto reports = checker.analyzeDirectory(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateDirectoryReport(path, reports);
            }
            break;
        }

        case 3: {  // Поиск стеганографии
            SteganographyChecker checker;
            if (fileChoice == 1) {
                auto result = checker.analyzeFile(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateSingleReport(path, result);
            }
            else {
                auto reports = checker.analyzeDirectory(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateDirectoryReport(path, reports);
            }
            break;
        }

        case 4: {  // Проверка скрытых расширений
            ExtensionChecker checker;
            if (fileChoice == 1) {
                auto result = checker.analyzeFile(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateSingleReport(path, result);
            }
            else {
                auto reports = checker.analyzeDirectory(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateDirectoryReport(path, reports);
            }
            break;
        }

        case 5: {
            PDFAnalyzer analyzer("rules.yar");
            if (fileChoice == 1) {
                auto result = analyzer.analyzeFile(path);
                ReportGenerator report;
                report.generateSingleReport(path, result);
                
            }
            else {
                auto reports = analyzer.analyzeDirectory(path);
                ReportGenerator report;
                report.generateDirectoryReport(path, reports);

            }
            break;
        }

        case 6:
            FullAnalyzer analyzer("rules.yar");

            if (fileChoice == 1) {
                auto result = analyzer.analyzeFile(path);
                std::cout << "\n";
                ReportGenerator report;
                report.generateSingleReport(path, result);
            }
            else {
                auto reports = analyzer.analyzeDirectory(path);
                ReportGenerator report;
                report.generateDirectoryReport(path, reports);
            }
            break;
        }

        std::cout << "\nНажмите Enter для возврата в меню...";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cin.get();
    }

    std::cout << "Выход из программы.\n";
    return 0;
}