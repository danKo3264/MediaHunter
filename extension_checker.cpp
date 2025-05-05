#include "extension_checker.h"
#include "file_reader.h"
#include "report_generator.h"
#include <iostream>
#include <filesystem>
#include <vector>
#include <string>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

std::vector<std::string> ExtensionChecker::analyzeFile(const std::string& filePath) {
    std::vector<std::string> reportLines;
    // Загрузка файла и определение формата по сигнатуре
    FileReader reader(filePath);
    std::vector<uint8_t> buffer;
    if (!reader.loadFile(buffer)) {
        std::cerr << "Ошибка: не удалось открыть файл: " << filePath << "\n";
        reportLines.push_back("Ошибка: не удалось открыть файл."); // ⬅️ Сохраняем сообщение в отчёт
        return reportLines;
    }
    std::string format = reader.detectFileType(buffer);

    // Получение расширений файла
    fs::path pathObj(filePath);
    std::string extension = pathObj.extension().string(); // с точкой, например ".jpg"
    std::string fullExt; // полное расширение, включая предыдущее, например ".jpg.exe"
    fs::path stemPath = pathObj.stem();
    if (stemPath.has_extension()) {
        fullExt = stemPath.extension().string() + extension;
    }

    // Снижение регистра расширения для сравнения
    std::string extLower = extension;
    std::transform(extLower.begin(), extLower.end(), extLower.begin(),
        [](unsigned char c) { return std::tolower(c); });

    // Проверка соответствия расширения и фактического формата
    bool extMismatch = false;
    if (format == "JPEG") {
        if (!(extLower == ".jpg" || extLower == ".jpeg")) extMismatch = true;
    }
    else if (format == "PNG") {
        if (extLower != ".png") extMismatch = true;
    }
    else if (format == "BMP") {
        if (extLower != ".bmp") extMismatch = true;
    }
    else if (format == "MP3") {
        if (extLower != ".mp3") extMismatch = true;
    }
    else if (format == "MP4") {
        if (extLower != ".mp4") extMismatch = true;
    }
    else if (format == "WebM") {
        if (extLower != ".webm") extMismatch = true;
    }
    else if (format == "MKV") {
        if (extLower != ".mkv") extMismatch = true;
    }
    else if (format == "AVI") {
        if (extLower != ".avi") extMismatch = true;
    }
    else if (format == "PSD") {
        if (extLower != ".psd") extMismatch = true;
    }
    else if (format == "HEVC") {
        if (!(extLower == ".hevc" || extLower == ".h265")) extMismatch = true;
    }
    else if (format == "AV1") {
        if (extLower != ".av1") extMismatch = true;
    }
    else if (format == "WebP") {
        if (extLower != ".webp") extMismatch = true;
    }
    else if (format == "TIFF") {
        if (!(extLower == ".tif" || extLower == ".tiff")) extMismatch = true;
    }
    else if (format == "CR2") {
        if (extLower != ".cr2") extMismatch = true;
    }
    else if (format == "NEF") {
        if (extLower != ".nef") extMismatch = true;
    }
    else if (format == "DNG") {
        if (extLower != ".dng") extMismatch = true;
    }
    else if (format == "EMF") {
        if (extLower != ".emf") extMismatch = true;
    }
    else if (format == "WMF") {
        if (extLower != ".wmf") extMismatch = true;
    }
    // Формат "Unknown" или прочие пропускаем

    // Проверка не-ASCII символов в расширении
    bool nonAsciiExt = false;
    for (char c : extension) {
        if (c == '.') continue;
        if (static_cast<unsigned char>(c) >= 128) {
            nonAsciiExt = true;
            break;
        }
    }

    // Проверка на невидимые или специальные символы в имени файла
    std::string filename = pathObj.filename().string();
    std::vector<std::pair<std::string, std::string>> specialChars = {
        {"\xE2\x80\x8B", "U+200B"}, // zero-width space
        {"\xE2\x80\x8C", "U+200C"}, // zero-width non-joiner
        {"\xE2\x80\x8D", "U+200D"}, // zero-width joiner
        {"\xEF\xBB\xBF", "U+FEFF"}, // zero-width no-break
        {"\xE2\x80\xAA", "U+202A"}, // left-to-right override
        {"\xE2\x80\xAB", "U+202B"}, // right-to-left override
        {"\xE2\x80\xAC", "U+202C"}, // pop directional formatting
        {"\xE2\x80\xAD", "U+202D"}, // left-to-right embedding
        {"\xE2\x80\xAE", "U+202E"}  // right-to-left override
    };
    std::vector<std::string> foundCodes;
    for (const auto& kv : specialChars) {
        if (filename.find(kv.first) != std::string::npos) {
            foundCodes.push_back(kv.second);
        }
    }
    bool hasInvisible = !foundCodes.empty();

    // Сбор комментариев о найденных проблемах
    std::string comment;
    if (extMismatch) {
        comment += "Несоответствие расширения фактическому типу";
    }
    if (nonAsciiExt) {
        if (!comment.empty()) comment += "; ";
        comment += "Расширение содержит не-ASCII символы";
    }
    if (hasInvisible) {
        if (!comment.empty()) comment += "; ";
        if (foundCodes.size() == 1) {
            comment += std::string("Найден невидимый символ: ") + foundCodes[0];
        }
        else {
            comment += "Найдены невидимые символы: ";
            for (size_t i = 0; i < foundCodes.size(); ++i) {
                comment += foundCodes[i];
                if (i + 1 < foundCodes.size()) comment += ", ";
            }
        }
    }
    if (comment.empty()) {
        comment = "-";
    }

    // Определение результата анализа (угроза или нет)
    bool threat = extMismatch || !fullExt.empty() || nonAsciiExt || hasInvisible;

    // Вывод результатов в консоль
    std::cout << "========================================\n";
    std::cout << "Анализ файла: " << filePath << "\n\n";
    std::cout << "Фактический тип: " << format << "\n";
    std::cout << "Расширение файла: " << (extension.empty() ? "-" : extension) << "\n";
    std::cout << "Двойное расширение: " << (fullExt.empty() ? "-" : fullExt) << "\n";
    std::cout << "Комментарий: " << comment << "\n\n";
    std::cout << "Результат: " << (threat ? "Потенциальная угроза" : "Угроз не обнаружено") << "\n";
    std::cout << "========================================\n";

    // Формирование отчёта для одного файла
    reportLines.push_back("Фактический тип: " + format);
    reportLines.push_back("Расширение файла: " + (extension.empty() ? "-" : extension));
    reportLines.push_back("Двойное расширение: " + (fullExt.empty() ? "-" : fullExt));
    reportLines.push_back("Комментарий: " + comment);
    reportLines.push_back("Результат: " + std::string(threat ? "Потенциальная угроза" : "Угроз не обнаружено"));

    return reportLines;
}

std::vector<std::pair<std::string, std::vector<std::string>>> ExtensionChecker::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> allReports;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        std::string filePath = entry.path().string();
        auto reportLines = analyzeFile(filePath);
        allReports.emplace_back(filePath, reportLines);
    }

    return allReports;
}