#include <iostream>
#include <string>
#include <filesystem>
#include <limits>
#include <vector>
#include <utility>
#include "file_reader.h"
#include "report_generator.h" // Модуль генерации отчётов

using namespace std;
namespace fs = std::filesystem;

// Функция для очистки консоли
void clearConsole() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// Отображение главного меню
void showMenu() {
    cout << "=== MediaHunter ===" << endl;
    cout << "Выберите тип анализа:" << endl;
    cout << "1) Анализ фото/видео файлов" << endl;
    cout << "2) Анализ метаданных файла" << endl;
    cout << "3) Поиск стеганографических встраиваний" << endl;
    cout << "4) Проверка скрытых расширений файлов" << endl;
    cout << "5) Общий анализ" << endl;
    cout << "0) Выход" << endl;
    cout << "Введите номер пункта: ";
}

// Отображение меню выбора режима работы (файл или директория)
void showFileMenu() {
    cout << "Выберите режим работы:" << endl;
    cout << "1) Анализ файла" << endl;
    cout << "2) Анализ директории с файлами" << endl;
    cout << "0) Назад" << endl;
    cout << "Введите номер пункта: ";
}

// Функция проверки корректности пути
bool isValidPath(const string& path, bool isFile) {
    try {
        if (isFile)
            return fs::is_regular_file(path);
        else
            return fs::is_directory(path);
    }
    catch (const fs::filesystem_error&) {
        return false;
    }
}

int main() {
    setlocale(LC_ALL, "Russian");
    int choice;
    do {
        clearConsole();
        showMenu();
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Ошибка: введите число!" << endl;
            cin.get();
            continue;
        }
        if (choice == 0)
            break;
        if (choice < 1 || choice > 5) {
            cout << "Ошибка: выберите корректный пункт." << endl;
            cin.ignore();
            cin.get();
            continue;
        }
        clearConsole();
        showFileMenu();
        int fileChoice;
        if (!(cin >> fileChoice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Ошибка: введите число!" << endl;
            cin.get();
            continue;
        }
        if (fileChoice == 0)
            continue;
        if (fileChoice < 1 || fileChoice > 2) {
            cout << "Ошибка: выберите корректный пункт." << endl;
            cin.ignore();
            cin.get();
            continue;
        }
        cout << "Введите путь к " << (fileChoice == 1 ? "файлу" : "директории") << ": ";
        string path;
        cin >> ws;
        getline(cin, path);
        if (!isValidPath(path, fileChoice == 1)) {
            cout << "Ошибка: путь недействителен!" << endl;
            cin.get();
            continue;
        }
        cout << "Запуск анализа..." << endl;
        // Если выбран анализ одного файла
        if (fileChoice == 1) {
            FileReader reader(path);
            vector<uint8_t> fileData;
            if (!reader.loadFile(fileData)) {
                cout << "Ошибка при чтении файла!" << endl;
            }
            else {
                string fileType = reader.detectFileType(fileData);
                cout << "Определённый тип файла: " << fileType << endl;
                bool threatFound = (fileType == "Unknown"); // Пример логики: если тип не определён, угроза обнаружена
                ReportGenerator report;
                report.generate(path, threatFound, "txt");
            }
        }
        // Если выбран анализ директории
        else {
            // Вектор для накопления результатов: <путь к файлу, статус угрозы>
            vector<pair<string, bool>> dirResults;
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    string filePath = entry.path().string();
                    cout << "Анализ файла: " << filePath << endl;
                    FileReader reader(filePath);
                    vector<uint8_t> fileData;
                    bool threatFound = false;
                    if (reader.loadFile(fileData)) {
                        string fileType = reader.detectFileType(fileData);
                        cout << "  -> Тип файла: " << fileType << endl;
                        threatFound = (fileType == "Unknown");
                    }
                    else {
                        cout << "  -> Ошибка чтения файла!" << endl;
                        threatFound = true;
                    }
                    dirResults.push_back(make_pair(filePath, threatFound));
                }
            }
            // Генерация сводного отчёта для всей директории
            ReportGenerator report;
            report.generateDirectoryReport(path, dirResults, "txt");
        }
        cout << "Нажмите Enter для возврата в меню..." << endl;
        cin.ignore();
        cin.get();
    } while (choice != 0);
    cout << "Выход из программы." << endl;
    return 0;
}
