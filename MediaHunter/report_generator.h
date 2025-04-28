#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include <string>
#include <vector>
#include <utility>

// Класс для сохранения отчётов анализа в файлы
class ReportGenerator {
public:
    // Генерация отчёта для одного файла
    void generateSingleReport(const std::string& filePath, const std::vector<std::string>& reportLines);

    // Генерация общего отчёта для директории
    void generateDirectoryReport(const std::string& dirPath, const std::vector<std::pair<std::string, std::vector<std::string>>>& fileReports);

private:
    // Запрос у пользователя разрешения на сохранение файла
    bool askUserToSave(const std::string& description);
};

#endif // REPORT_GENERATOR_H
