#ifndef EXTENSION_CHECKER_H
#define EXTENSION_CHECKER_H

#include <string>
#include <vector>

class ExtensionChecker {
public:
    std::vector<std::string> analyzeFile(const std::string& filePath);
    std::vector<std::pair<std::string, std::vector<std::string>>> analyzeDirectory(const std::string& dirPath);
};

#endif // EXTENSION_CHECKER_H
