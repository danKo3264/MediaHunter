#include "pdf_analyzer.h"
#include "file_reader.h"
#include "report_generator.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <ostream>
#include <array>
#include <chrono>
#include <cmath>

// ─── PoDoFo ─────────────────────────────────────────────────────────────────────
#include <podofo/podofo.h>
using namespace PoDoFo;

namespace fs = std::filesystem;

class PodofoOutputSuppressor {
    std::streambuf* oldCout_;
    std::streambuf* oldCerr_;
public:
    PodofoOutputSuppressor()
        : oldCout_(std::cout.rdbuf()), oldCerr_(std::cerr.rdbuf())
    {
        // Перенаправляем вывод в “никуда”
        std::cout.rdbuf(nullptr);
        std::cerr.rdbuf(nullptr);
    }
    ~PodofoOutputSuppressor() {
        // Восстанавливаем оригинальные буферы
        std::cout.rdbuf(oldCout_);
        std::cerr.rdbuf(oldCerr_);
    }
};

PDFAnalyzer::PDFAnalyzer(const std::string& rulesPath, bool deepStreamAnalysis)
  : yaraScanner_(rulesPath)
  , deep_(deepStreamAnalysis)
{}

std::vector<std::string> PDFAnalyzer::analyzeFile(const std::string& filePath) {
    std::vector<std::string> reportLines;
    FileReader reader(filePath);
    std::vector<uint8_t> buffer;
    if (!reader.loadFile(buffer)) {
        std::cerr << "Ошибка: не удалось открыть файл: " << filePath << "\n";
        reportLines.push_back("Ошибка: не удалось открыть файл.");
        return reportLines;
    }
    // Получение информации о файле
    uintmax_t fileSize = 0;
    try {
        fileSize = fs::file_size(filePath);
    }
    catch (...) {
        fileSize = 0;
    }
    std::string dateStr = "неизвестна";
    try {
        auto ftime = fs::last_write_time(filePath);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);
        std::tm tmBuf{};
        if (localtime_s(&tmBuf, &cftime) == 0) {
            char timeBuf[20];
            if (std::strftime(timeBuf, sizeof(timeBuf), "%d.%m.%Y %H:%M:%S", &tmBuf)) {
                dateStr = timeBuf;
            }
        }
    }
    catch (...) {
        dateStr = "неизвестна";
    }
    // Проверка заголовка PDF
    bool validHeader = (buffer.size() >= 5 &&
        buffer[0] == '%' && buffer[1] == 'P' &&
        buffer[2] == 'D' && buffer[3] == 'F' && buffer[4] == '-');
    if (!validHeader) {
        std::string line = "Файл не является PDF-документом (некорректный заголовок).";
        std::cout << line << "\n";
        reportLines.push_back(line);
        return reportLines;
    }
    // Извлечение версии PDF из заголовка (если указана)
    std::string pdfVersion;
    if (buffer.size() >= 8 && std::isdigit(buffer[5]) && buffer[6] == '.' && std::isdigit(buffer[7])) {
        pdfVersion.push_back(static_cast<char>(buffer[5]));
        pdfVersion.push_back('.');
        pdfVersion.push_back(static_cast<char>(buffer[7]));
    }
    // Вывод общей информации
    std::cout << "========================================\n";
    std::cout << "Анализ файла: " << filePath << "\n";
    std::cout << "Формат: PDF\n";
    std::cout << "Размер: " << fileSize << " байт\n";
    std::cout << "Дата изменения: " << dateStr << "\n";
    if (!pdfVersion.empty()) {
        std::cout << "PDF-версия: " << pdfVersion << "\n";
        reportLines.push_back("PDF-версия: " + pdfVersion);
    }
    reportLines.push_back("Формат: PDF");
    reportLines.push_back("Размер: " + std::to_string(fileSize) + " байт");
    reportLines.push_back("Дата изменения: " + dateStr);
    // Загрузка PDF-документа с помощью библиотеки PoDoFo
    PdfMemDocument doc;
    bool encrypted = false;
    try {
        PodofoOutputSuppressor suppress;
        doc.Load(filePath.c_str());
    }
    catch (PdfError& e) {
        std::cerr << "Ошибка: не удалось разобрать PDF-файл (" << e.what() << ")\n";
        reportLines.push_back(std::string("Ошибка разбора PDF: ") + e.what());
        return reportLines;
    }
    if (doc.IsEncrypted()) {
        encrypted = true;
        std::string encLine = "- [!] Обнаружено шифрование PDF (возможно, файл защищён паролем).";
        std::cout << encLine << "\n";
        reportLines.push_back(encLine);
    }
    // Проверка таблицы кросс-ссылок (xref)
    std::string bufferStr(reinterpret_cast<char*>(buffer.data()), buffer.size());
    size_t xrefCount = 0;
    size_t pos = 0;
    while ((pos = bufferStr.find("xref", pos)) != std::string::npos) {
        xrefCount++;
        pos += 4;
    }
    bool hasXRefStream = (bufferStr.find("/Type") != std::string::npos && bufferStr.find("/XRef") != std::string::npos);
    if (xrefCount == 0) {
        if (hasXRefStream) {
            std::string line = "Cross-reference: используется поток XRef.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        else {
            std::string line = "- [!] Таблица xref не найдена.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
    }
    else {
        std::string line = "Секции xref: " + std::to_string(xrefCount);
        std::cout << line << "\n";
        reportLines.push_back(line);
        if (xrefCount > 1) {
            std::string mline = "- [!] Обнаружено несколько xref-секций (инкрементальные обновления).";
            std::cout << mline << "\n";
            reportLines.push_back(mline);
        }
    }
    // Проверка завершающего трейлера (%%EOF)
    bool validTrailer = false;
    size_t eofPos = bufferStr.rfind("%%EOF");
    if (eofPos == std::string::npos) {
        std::string line = "- [!] Трейлер PDF (%%EOF) не найден.";
        std::cout << line << "\n";
        reportLines.push_back(line);
    }
    else {
        validTrailer = true;
        size_t afterPos = eofPos + 5;
        // Пропуск любых пробельных символов после %%EOF
        while (afterPos < buffer.size() && (buffer[afterPos] == '\r' || buffer[afterPos] == '\n' ||
            buffer[afterPos] == ' ' || buffer[afterPos] == '\t')) {
            afterPos++;
        }
        if (afterPos < buffer.size()) {
            size_t extraBytes = buffer.size() - afterPos;
            std::string line = "- [!] Обнаружены данные после %%EOF: " + std::to_string(extraBytes) + " байт.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
    }

    // Анализ объектов PDF
    bool hasJS = false;
    bool hasLaunch = false;
    bool hasEmbeddedFile = false;
    bool hasRichMedia = false;
    bool hasXFA = false;
    bool highEntropyFound = false;
    auto& objects = doc.GetObjects();
    size_t objCount = objects.GetObjectCount();
    std::string line = "Количество объектов: " + std::to_string(objCount);
    std::cout << line << "\n";
    reportLines.push_back(line);
    for (size_t i = 0; i < objCount; ++i) {
        PdfReference ref(static_cast<uint32_t>(i + 1), 0);
        PdfObject* obj = objects.GetObject(ref);
        if (!obj) continue;
        // Проверка словаря объекта на ключевые элементы
        if (obj->IsDictionary()) {
            const PdfDictionary& dict = obj->GetDictionary();
            if (dict.HasKey(PdfName("JS")) || dict.HasKey(PdfName("JavaScript"))) {
                hasJS = true;
            }
            if (dict.HasKey(PdfName("OpenAction"))) {
                const PdfObject* oa = dict.GetKey(PdfName("OpenAction"));
                if (oa) {
                    // Если OpenAction является косвенной ссылкой
                    if (oa->IsReference()) {
                        PdfReference ref = oa->GetReference();
                        const PdfObject* act = objects.GetObject(ref);
                        if (act && act->IsDictionary()) {
                            const PdfDictionary& adict = act->GetDictionary();
                            if (adict.HasKey(PdfName("S"))) {
                                const PdfObject* subtype = adict.GetKey(PdfName("S"));
                                if (subtype && subtype->IsName()) {
                                    std::string sName = subtype->GetName().GetString();
                                    if (sName == "JavaScript") {
                                        hasJS = true;
                                    }
                                    else if (sName == "Launch") {
                                        hasLaunch = true;
                                    }
                                }
                            }
                        }
                    }
                    else if (oa->IsDictionary()) {
                        const PdfDictionary& adict = oa->GetDictionary();
                        if (adict.HasKey(PdfName("S"))) {
                            const PdfObject* subtype = adict.GetKey(PdfName("S"));
                            if (subtype && subtype->IsName()) {
                                std::string sName = subtype->GetName().GetString();
                                if (sName == "JavaScript") {
                                    hasJS = true;
                                }
                                else if (sName == "Launch") {
                                    hasLaunch = true;
                                }
                            }
                        }
                    }
                }
            }
            if (dict.HasKey(PdfName("Type"))) {
                const PdfObject* typeObj = dict.GetKey(PdfName("Type"));
                if (typeObj && typeObj->IsName()) {
                    std::string typeName = typeObj->GetName().GetString();
                    if (typeName == "EmbeddedFile") {
                        hasEmbeddedFile = true;
                    }
                    else if (typeName == "RichMedia") {
                        hasRichMedia = true;
                    }
                    else if (typeName == "Catalog") {
                        // Проверка на XFA в форме AcroForm
                        if (dict.HasKey(PdfName("AcroForm"))) {
                            const PdfObject* acroObj = dict.GetKey(PdfName("AcroForm"));
                            if (acroObj) {
                                if (acroObj->IsReference()) {
                                    acroObj = objects.GetObject(acroObj->GetReference());
                                }
                                if (acroObj && acroObj->IsDictionary()) {
                                    const PdfDictionary& acroDict = acroObj->GetDictionary();
                                    if (acroDict.HasKey(PdfName("XFA"))) {
                                        hasXFA = true;
                                    }
                                }
                            }
                        }
                        // Проверка наличия Name-директорий JavaScript или EmbeddedFiles
                        if (dict.HasKey(PdfName("Names"))) {
                            const PdfObject* namesObj = dict.GetKey(PdfName("Names"));
                            if (namesObj) {
                                if (namesObj->IsReference()) {
                                    namesObj = objects.GetObject(namesObj->GetReference());
                                }
                                if (namesObj && namesObj->IsDictionary()) {
                                    const PdfDictionary& namesDict = namesObj->GetDictionary();
                                    if (namesDict.HasKey(PdfName("JavaScript"))) {
                                        hasJS = true;
                                    }
                                    if (namesDict.HasKey(PdfName("EmbeddedFiles"))) {
                                        hasEmbeddedFile = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (dict.HasKey(PdfName("S"))) {
                const PdfObject* sObj = dict.GetKey(PdfName("S"));
                if (sObj && sObj->IsName()) {
                    std::string sName = sObj->GetName().GetString();
                    if (sName == "JavaScript") {
                        hasJS = true;
                    }
                    else if (sName == "Launch") {
                        hasLaunch = true;
                    }
                }
            }
            if (dict.HasKey(PdfName("Subtype"))) {
                const PdfObject* subObj = dict.GetKey(PdfName("Subtype"));
                if (subObj && subObj->IsName()) {
                    std::string subName = subObj->GetName().GetString();
                    if (subName == "EmbeddedFile" || subName == "FileAttachment") {
                        hasEmbeddedFile = true;
                    }
                    if (subName == "RichMedia") {
                        hasRichMedia = true;
                    }
                }
            }
            if (dict.HasKey(PdfName("XFA"))) {
                hasXFA = true;
            }
        }
        // Проверка энтропии потоков данных
        if (obj->HasStream()) {
            bool isImageStream = false;
            if (obj->IsDictionary()) {
                const PdfDictionary& dict = obj->GetDictionary();
                if (dict.HasKey(PdfName("Subtype"))) {
                    const PdfObject* sub = dict.GetKey(PdfName("Subtype"));
                    if (sub && sub->IsName()) {
                        std::string subName = sub->GetName().GetString();
                        if (subName == "Image") {
                            isImageStream = true;
                        }
                    }
                }
            }
            if (!isImageStream) {
                if (obj->HasStream()) {
                    PdfObjectStream& stream = obj->GetOrCreateStream();
                    size_t length = stream.GetLength();
                    if (length > 0) {
                        charbuff_t<> buffer;
                        stream.CopyToSafe(buffer);
                        const char* buf = buffer.c_str();
                        if (buf) {
                            size_t outLen = static_cast<size_t>(length);
                            std::array<size_t, 256> freq{};
                            freq.fill(0);
                            for (size_t k = 0; k < outLen; ++k) {
                                unsigned char c = static_cast<unsigned char>(buf[k]);
                                freq[c]++;
                            }
                            double entropy = 0.0;
                            for (size_t f : freq) {
                                if (f == 0) continue;
                                double p = static_cast<double>(f) / outLen;
                                entropy -= p * std::log2(p);
                            }
                            if (entropy > 7.5 && outLen > 100) {
                                highEntropyFound = true;
                                std::string line = "- [!] Обнаружен поток с высокой энтропией: " + std::to_string(entropy) + " бит.";
                                std::cout << line << "\n";
                                reportLines.push_back(line);
                            }
                        }
                    }

                }
            }
        }
        // Отчёт по обнаруженным объектам
        if (hasJS) {
            std::string line = "- [!] Обнаружен JavaScript-код.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        if (hasLaunch) {
            std::string line = "- [!] Обнаружено действие Launch (запуск внешнего приложения).";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        if (hasEmbeddedFile) {
            std::string line = "- [!] Обнаружены вложенные файлы.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        if (hasRichMedia) {
            std::string line = "- [!] Обнаружен RichMedia-контент.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        if (hasXFA) {
            std::string line = "- [!] Обнаружена XFA-форма.";
            std::cout << line << "\n";
            reportLines.push_back(line);
        }
        // Итоговый результат анализа для PDF
        bool threat = false;
        if (encrypted || !validTrailer || xrefCount == 0 || xrefCount > 1 || highEntropyFound || hasJS || hasLaunch || hasEmbeddedFile || hasRichMedia || hasXFA) {
            threat = true;
        }
        std::string resultLine = "Результат: " + std::string(threat ? "Потенциальная угроза" : "Угроз не обнаружено");
        std::cout << resultLine << "\n";
        std::cout << "========================================\n";
        reportLines.push_back(resultLine);
        return reportLines;
    }
}

std::vector<std::pair<std::string, std::vector<std::string>>> PDFAnalyzer::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> reports;
    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        std::string filePath = entry.path().string();
        auto lines = analyzeFile(filePath);
        reports.emplace_back(filePath, lines);
    }
    return reports;
}
