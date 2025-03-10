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
        cerr << "ќшибка: не удалось создать файл отчЄта: " << reportFileName << endl;
        return;
    }
    if (format == "html") {
        reportFile << "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"UTF-8\">\n    <title>ќтчЄт по файлу</title>\n</head>\n<body>\n";
        reportFile << "<h1>ќтчЄт по файлу: " << filePath << "</h1>\n";
        reportFile << "<p>–езультат анализа: " << (threatsFound ? "<span style=\"color:red;\">”грозы обнаружены</span>" : "<span style=\"color:green;\">”грозы не обнаружены</span>") << "</p>\n";
        reportFile << "</body>\n</html>\n";
    }
    else {
        reportFile << "ќтчЄт по файлу: " << filePath << "\n";
        reportFile << "–езультат анализа: " << (threatsFound ? "”грозы обнаружены" : "”грозы не обнаружены") << "\n";
    }
    reportFile.close();
    cout << "ќтчЄт сохранЄн в файле: " << reportFileName << endl;
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
        cerr << "ќшибка: не удалось создать файл отчЄта: " << reportFileName << endl;
        return;
    }
    if (format == "html") {
        reportFile << "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"UTF-8\">\n    <title>ќтчЄт по директории</title>\n</head>\n<body>\n";
        reportFile << "<h1>ќтчЄт по директории: " << dirPath << "</h1>\n";
        reportFile << "<table border=\"1\">\n<tr><th>‘айл</th><th>–езультат анализа</th></tr>\n";
        for (const auto& [filePath, threatFound] : results) {
            reportFile << "<tr><td>" << filePath << "</td><td>"
                << (threatFound ? "<span style=\"color:red;\">”грозы обнаружены</span>"
                    : "<span style=\"color:green;\">”грозы не обнаружены</span>")
                << "</td></tr>\n";
        }
        reportFile << "</table>\n</body>\n</html>\n";
    }
    else {
        reportFile << "ќтчЄт по директории: " << dirPath << "\n\n";
        for (const auto& [filePath, threatFound] : results) {
            reportFile << "‘айл: " << filePath << "\n–езультат анализа: "
                << (threatFound ? "”грозы обнаружены" : "”грозы не обнаружены") << "\n\n";
        }
    }
    reportFile.close();
    cout << "ќбщий отчЄт по директории сохранЄн в файле: " << reportFileName << endl;
}
