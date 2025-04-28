#ifndef STEGANOGRAPHY_CHECKER_H
#define STEGANOGRAPHY_CHECKER_H

#include <string>
#include <vector>
#include <cstdint>

class SteganographyChecker {
public:
    // Анализ одного файла и директории
    void analyzeFile(const std::string& filePath);
    void analyzeDirectory(const std::string& dirPath);

private:
    bool analyzeBuffer(const std::string& filePath, const std::string& format, const std::vector<uint8_t>& buffer, std::vector<std::string>& reportLines);
    
    // Определение, нужен ли LSB-анализ для данного формата
    bool isLSBRelevantFormat(const std::string& format) const;
    bool performLSBAnalysis(const std::vector<uint8_t>& buffer, std::vector<std::string>& reportLines);

};

#endif // STEGANOGRAPHY_CHECKER_H
