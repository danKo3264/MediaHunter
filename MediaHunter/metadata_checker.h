#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <string>
#include <vector>

class MetadataChecker {
public:
    // Показать метаданные одного файла
    std::vector<std::string> showMetadata(const std::string& filePath);

    // Новый функционал: анализ одного файла и сохранение отчёта
    void analyzeFile(const std::string& filePath);

    // Новый функционал: анализ директории и сохранение общего отчёта
    void analyzeDirectory(const std::string& dirPath);
};

#endif // METADATA_CHECKER_H
