#include "report_generator.h"
#include <fstream>
#include <iostream>

using namespace std;

void ReportGenerator::generate(const string& filePath, bool threatsFound, const string& format) {
    string reportFileName;
    if (format == "html") {
        reportFileName = filePath + ".report.html";
    }
    else {
        reportFileName = filePath + ".report.txt";
    }
    ofstream reportFile(reportFileName);
    if (!reportFile) {
        cerr << "������: �� ������� ������� ���� ������: " << reportFileName << endl;
        return;
    }
    if (format == "html") {
        reportFile << "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"UTF-8\">\n    <title>����� �� �����</title>\n</head>\n<body>\n";
        reportFile << "<h1>����� �� �����: " << filePath << "</h1>\n";
        reportFile << "<p>��������� �������: " << (threatsFound ? "<span style=\"color:red;\">������ ����������</span>" : "<span style=\"color:green;\">������ �� ����������</span>") << "</p>\n";
        reportFile << "</body>\n</html>\n";
    }
    else {
        reportFile << "����� �� �����: " << filePath << "\n";
        reportFile << "��������� �������: " << (threatsFound ? "������ ����������" : "������ �� ����������") << "\n";
    }
    reportFile.close();
    cout << "����� ������� � �����: " << reportFileName << endl;
}

void ReportGenerator::generateDirectoryReport(const string& dirPath, const vector<pair<string, bool>>& results, const string& format) {
    string reportFileName;
    if (format == "html") {
        reportFileName = dirPath + "/directory_report.html";
    }
    else {
        reportFileName = dirPath + "/directory_report.txt";
    }
    ofstream reportFile(reportFileName);
    if (!reportFile) {
        cerr << "������: �� ������� ������� ���� ������: " << reportFileName << endl;
        return;
    }
    if (format == "html") {
        reportFile << "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"UTF-8\">\n    <title>����� �� ����������</title>\n</head>\n<body>\n";
        reportFile << "<h1>����� �� ����������: " << dirPath << "</h1>\n";
        reportFile << "<table border=\"1\">\n<tr><th>����</th><th>��������� �������</th></tr>\n";
        for (const auto& [filePath, threatFound] : results) {
            reportFile << "<tr><td>" << filePath << "</td><td>"
                << (threatFound ? "<span style=\"color:red;\">������ ����������</span>"
                    : "<span style=\"color:green;\">������ �� ����������</span>")
                << "</td></tr>\n";
        }
        reportFile << "</table>\n</body>\n</html>\n";
    }
    else {
        reportFile << "����� �� ����������: " << dirPath << "\n\n";
        for (const auto& [filePath, threatFound] : results) {
            reportFile << "����: " << filePath << "\n��������� �������: "
                << (threatFound ? "������ ����������" : "������ �� ����������") << "\n\n";
        }
    }
    reportFile.close();
    cout << "����� ����� �� ���������� ������� � �����: " << reportFileName << endl;
}
