#ifndef METADATA_CHECKER_H
#define METADATA_CHECKER_H

#include <string>
#include <vector>

class MetadataChecker {
public:
    std::vector<std::string> analyzeFile(const std::string& filePath);
    std::vector<std::pair<std::string, std::vector<std::string>>> analyzeDirectory(const std::string& dirPath);
};

#endif // METADATA_CHECKER_H
