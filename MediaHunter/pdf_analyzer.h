#ifndef PDF_ANALYZER_H
#define PDF_ANALYZER_H

#include <string>
#include <vector>
#include <utility>
#include <cstdint>

#include "signature_scanner.h"
#include "file_reader.h"

class PDFAnalyzer {
public:
    enum class ThreatLevel {
        None,
        Suspicious,
        Malicious
    };

    explicit PDFAnalyzer(const std::string& rulesPath = "pdf_rules.yar",
        bool deepStreamAnalysis = true);

    std::vector<std::string> analyzeFile(const std::string& filePath);

    std::vector<std::pair<std::string, std::vector<std::string>>>
        analyzeDirectory(const std::string& dirPath);

private:
    struct PDFObjectInfo {
        uint32_t number;
        uint32_t generation;
        size_t offset;
        size_t length;
        std::string raw;
    };

    bool loadFile(const std::string& filePath,
        std::vector<uint8_t>& buffer) const;

    bool isPDFHeaderValid(const std::vector<uint8_t>& buf) const;
    bool isPDFTrailerValid(const std::vector<uint8_t>& buf) const;

    bool extractObjects(const std::vector<uint8_t>& buf,
        std::vector<PDFObjectInfo>& objects,
        std::vector<std::string>& report) const;

    bool analyzeObject(const PDFObjectInfo& obj,
        std::vector<std::string>& report,
        ThreatLevel& tl) const;

    bool detectJavaScript(const std::string& stream) const;
    bool detectLaunchAction(const std::string& dict) const;
    bool detectOpenAction(const std::string& dict) const;
    bool detectEmbeddedFile(const std::string& dict) const;
    bool detectRichMedia(const std::string& dict) const;
    bool detectXFAForms(const std::string& dict) const;
    bool detectSuspiciousURLs(const std::string& text) const;
    bool detectNullEncryptionPwd(const std::string& dict) const;
    bool detectHighEntropyStream(const std::vector<uint8_t>& data,
        double& entropy) const;

    ThreatLevel scoreHeuristics(const std::vector<std::string>& findings) const;

    SignatureScanner yaraScanner_;
    bool deep_;
};

#endif // PDF_ANALYZER_H
