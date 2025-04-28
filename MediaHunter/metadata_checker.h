#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <string>
#include <vector>

class MetadataChecker {
public:
    // �������� ���������� ������ �����
    std::vector<std::string> showMetadata(const std::string& filePath);

    // ����� ����������: ������ ������ ����� � ���������� ������
    void analyzeFile(const std::string& filePath);

    // ����� ����������: ������ ���������� � ���������� ������ ������
    void analyzeDirectory(const std::string& dirPath);
};

#endif // METADATA_CHECKER_H
