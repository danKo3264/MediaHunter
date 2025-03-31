#pragma once
#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <string>
#include <vector>

using namespace std;

class MetadataChecker {
public:
    MetadataChecker();

    // ���������� ���������� � ������� � ���������� ������ ��� ���������� ��������
    vector<string> showMetadata(const string& filePath);

    // ������������ ���������� � .txt ����
    bool exportMetadataToTxt(const vector<string>& metadataLines, const string& outputPath);
};

#endif // METADATA_CHECKER_H
