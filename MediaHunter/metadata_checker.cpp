#include "metadata_checker.h"
#include <iostream>
#include <fstream>
#include <cstdio>  // для _popen
#include <cstdlib>

using namespace std;

MetadataChecker::MetadataChecker() {}

vector<string> MetadataChecker::showMetadata(const string& filePath) {
    vector<string> lines;

    cout << "----- Метаданные файла -----" << endl;
    string command = "exiftool \"" + filePath + "\"";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        cout << "Ошибка: не удалось запустить ExifTool." << endl;
        return lines;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe)) {
        string line(buffer);
        cout << line;
        lines.push_back(line);
    }

    _pclose(pipe);
    cout << "-----------------------------" << endl;
    return lines;
}

bool MetadataChecker::exportMetadataToTxt(const vector<string>& metadataLines, const string& outputPath) {
    ofstream outFile(outputPath);
    if (!outFile.is_open()) {
        cout << "Ошибка: не удалось создать файл для записи." << endl;
        return false;
    }

    for (const auto& line : metadataLines) {
        outFile << line;
    }

    outFile.close();
    cout << "Метаданные успешно экспортированы в файл: " << outputPath << endl;
    return true;
}
