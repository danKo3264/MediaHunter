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

#include "file_reader.h"
#include "report_generator.h"
#include "metadata_checker.h"
#include "steganography_checker.h"
#include "signature_scanner.h"

using namespace std;
namespace fs = std::filesystem;

// ������� �������
void clearConsole() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// ������� ����
void showMenu() {
    cout << "=== MediaHunter ===\n"
        << "�������� ��� �������:\n"
        << "1) ������ ����/����� ������\n"
        << "2) ������ ���������� �����\n"
        << "3) ����� ������������������ �����������\n"
        << "4) �������� ������� ���������� ������\n"
        << "5) ����� ������\n"
        << "0) �����\n"
        << "������� ����� ������: ";
}

// ���� ������ ����� ��� ����������
void showFileMenu() {
    cout << "�������� ����� ������:\n"
        << "1) ������ �����\n"
        << "2) ������ ���������� � �������\n"
        << "0) �����\n"
        << "������� ����� ������: ";
}

// �������� ������������ ����
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
            cout << "������: ������� �����!\n";
            cin.get();
            continue;
        }
        if (choice == 0) break;
        if (choice < 1 || choice > 5) {
            cout << "������: �������� ���������� �����.\n";
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
            cout << "������: ������� �����!\n";
            cin.get();
            continue;
        }
        if (fileChoice == 0) continue;
        if (fileChoice < 1 || fileChoice > 2) {
            cout << "������: �������� ���������� �����.\n";
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cin.get();
            continue;
        }

        cout << "������� ���� � "
            << (fileChoice == 1 ? "�����" : "����������")
            << ": ";
        string path;
        cin >> ws;
        getline(cin, path);

        if (!isValidPath(path, fileChoice == 1)) {
            cout << "������: ���� ��������������!\n";
            cin.get();
            continue;
        }

        cout << "\n������ �������...\n\n";

        switch (choice) {
        case 1: {  // ������ ����/����� (����������� ������ YARA)
            try {
                SignatureScanner scanner("rules.yar");

                if (fileChoice == 1) {
                    std::string threat = scanner.analyzeFile(path);
                    cout << "\n========================================\n";
                    cout << "������ �����: " << path << "\n\n";
                    if (threat == "OK") {
                        cout << "���������: ����� �� ����������\n";
                    }
                    else {
                        cout << "���������: ���������� ������ " << threat << "\n";
                    }
                    cout << "========================================\n\n";

                    // ��������� ��������� � �����
                    ReportGenerator report;
                    vector<string> lines;
                    if (threat == "OK") {
                        lines.push_back("����� �� ����������");
                    }
                    else {
                        lines.push_back("���������� ������ " + threat);
                    }
                    report.generateSingleReport(path, lines);
                }
                else {
                    vector<pair<string, vector<string>>> allReports;
                    for (const auto& entry : fs::directory_iterator(path)) {
                        if (!entry.is_regular_file()) continue;
                        string filePath = entry.path().string();
                        std::string threat = scanner.analyzeFile(filePath);
                        cout << "\n========================================\n";
                        cout << "������ �����: " << filePath << "\n\n";
                        if (threat == "OK") {
                            cout << "���������: ����� �� ����������\n";
                        }
                        else {
                            cout << "���������: ���������� ������ " << threat << "\n";
                        }
                        cout << "========================================\n";

                        vector<string> lines;
                        if (threat == "OK") {
                            lines.push_back("����� �� ����������");
                        }
                        else {
                            lines.push_back("���������� ������ " + threat);
                        }
                        allReports.emplace_back(filePath, lines);
                    }
                    cout << "\n";
                    ReportGenerator report;
                    report.generateDirectoryReport(path, allReports);
                }
            }
            catch (const std::runtime_error& ex) {
                cerr << "������ ������������: " << ex.what() << "\n";
            }
            break;
        }

        case 2: {  // ������ ����������
            MetadataChecker checker;
            if (fileChoice == 1) {
                checker.analyzeFile(path);
            }
            else {
                checker.analyzeDirectory(path);
            }
            break;
        }

        case 3: {  // ����� �������������
            SteganographyChecker checker;
            if (fileChoice == 1)
                checker.analyzeFile(path);
            else
                checker.analyzeDirectory(path);
            break;
        }

        case 4:
            cout << "������ �������� ������� ���������� ���� �� ����������.\n";
            break;

        case 5:
            cout << "����� ������ ���� �� ����������.\n";
            break;
        }

        cout << "\n������� Enter ��� �������� � ����...";
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cin.get();
    }

    cout << "����� �� ���������.\n";
    return 0;
}
