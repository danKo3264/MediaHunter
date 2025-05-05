#ifndef FULL_ANALYZER_H
#define FULL_ANALYZER_H

#include <string>
#include <vector>
#include "signature_scanner.h"
#include "file_reader.h"
#include "report_generator.h"

class FullAnalyzer {
public:
    explicit FullAnalyzer(const std::string& rulesPath = "rules.yar");

    std::vector<std::string> analyzeFile(const std::string& filePath);
    std::vector<std::pair<std::string, std::vector<std::string>>> analyzeDirectory(const std::string& dirPath);

private:
    SignatureScanner scanner_;  // YARA-based signature scanner
};

#endif
