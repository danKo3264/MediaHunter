#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include <string>
#include <vector>
#include <utility>

using namespace std;

class ReportGenerator {
public:
    // ��������� ������ ��� ���������� �����
    void generate(const string& filePath, bool threatsFound, const string& format = "txt");

    // ��������� �������� ������ ��� ����������
    void generateDirectoryReport(const string& dirPath, const vector<pair<string, bool>>& results, const string& format = "txt");
};

#endif // REPORT_GENERATOR_H
