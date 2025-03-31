#pragma once
#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <string>
#include <vector>

using namespace std;

class MetadataChecker {
public:
    MetadataChecker();

    // Показывает метаданные в консоли и возвращает строки для возможного экспорта
    vector<string> showMetadata(const string& filePath);

    // Экспортирует метаданные в .txt файл
    bool exportMetadataToTxt(const vector<string>& metadataLines, const string& outputPath);
};

#endif // METADATA_CHECKER_H
