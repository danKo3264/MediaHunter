#include <iostream>
#include <string>
#include <filesystem>
#include <limits>
#include <vector>
#include <utility>
#include "file_reader.h"
#include "report_generator.h" // ������ ��������� �������

using namespace std;
namespace fs = std::filesystem;

// ������� ��� ������� �������
void clearConsole() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

// ����������� �������� ����
void showMenu() {
    cout << "=== MediaHunter ===" << endl;
    cout << "�������� ��� �������:" << endl;
    cout << "1) ������ ����/����� ������" << endl;
    cout << "2) ������ ���������� �����" << endl;
    cout << "3) ����� ������������������ �����������" << endl;
    cout << "4) �������� ������� ���������� ������" << endl;
    cout << "5) ����� ������" << endl;
    cout << "0) �����" << endl;
    cout << "������� ����� ������: ";
}

// ����������� ���� ������ ������ ������ (���� ��� ����������)
void showFileMenu() {
    cout << "�������� ����� ������:" << endl;
    cout << "1) ������ �����" << endl;
    cout << "2) ������ ���������� � �������" << endl;
    cout << "0) �����" << endl;
    cout << "������� ����� ������: ";
}

// ������� �������� ������������ ����
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
            cout << "������: ������� �����!" << endl;
            cin.get();
            continue;
        }
        if (choice == 0)
            break;
        if (choice < 1 || choice > 5) {
            cout << "������: �������� ���������� �����." << endl;
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
            cout << "������: ������� �����!" << endl;
            cin.get();
            continue;
        }
        if (fileChoice == 0)
            continue;
        if (fileChoice < 1 || fileChoice > 2) {
            cout << "������: �������� ���������� �����." << endl;
            cin.ignore();
            cin.get();
            continue;
        }
        cout << "������� ���� � " << (fileChoice == 1 ? "�����" : "����������") << ": ";
        string path;
        cin >> ws;
        getline(cin, path);
        if (!isValidPath(path, fileChoice == 1)) {
            cout << "������: ���� ��������������!" << endl;
            cin.get();
            continue;
        }
        cout << "������ �������..." << endl;
        // ���� ������ ������ ������ �����
        if (fileChoice == 1) {
            FileReader reader(path);
            vector<uint8_t> fileData;
            if (!reader.loadFile(fileData)) {
                cout << "������ ��� ������ �����!" << endl;
            }
            else {
                string fileType = reader.detectFileType(fileData);
                cout << "����������� ��� �����: " << fileType << endl;
                bool threatFound = (fileType == "Unknown"); // ������ ������: ���� ��� �� ��������, ������ ����������
                ReportGenerator report;
                report.generate(path, threatFound, "txt");
            }
        }
        // ���� ������ ������ ����������
        else {
            // ������ ��� ���������� �����������: <���� � �����, ������ ������>
            vector<pair<string, bool>> dirResults;
            for (const auto& entry : fs::directory_iterator(path)) {
                if (entry.is_regular_file()) {
                    string filePath = entry.path().string();
                    cout << "������ �����: " << filePath << endl;
                    FileReader reader(filePath);
                    vector<uint8_t> fileData;
                    bool threatFound = false;
                    if (reader.loadFile(fileData)) {
                        string fileType = reader.detectFileType(fileData);
                        cout << "  -> ��� �����: " << fileType << endl;
                        threatFound = (fileType == "Unknown");
                    }
                    else {
                        cout << "  -> ������ ������ �����!" << endl;
                        threatFound = true;
                    }
                    dirResults.push_back(make_pair(filePath, threatFound));
                }
            }
            // ��������� �������� ������ ��� ���� ����������
            ReportGenerator report;
            report.generateDirectoryReport(path, dirResults, "txt");
        }
        cout << "������� Enter ��� �������� � ����..." << endl;
        cin.ignore();
        cin.get();
    } while (choice != 0);
    cout << "����� �� ���������." << endl;
    return 0;
}
