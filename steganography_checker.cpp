#include "steganography_checker.h"
#include "file_reader.h"
#include "report_generator.h"
#include <iostream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <cmath>

namespace fs = std::filesystem;

std::vector<std::string> SteganographyChecker::analyzeFile(const std::string& filePath) {
    std::vector<std::string> reportLines;
    FileReader reader(filePath);
    std::vector<uint8_t> buffer;
    if (!reader.loadFile(buffer)) {
        std::cout << "Ошибка: не удалось открыть файл: " << filePath << "\n";
        reportLines.push_back("Ошибка: не удалось открыть файл.");
        return reportLines;
    }
    std::string format = reader.detectFileType(buffer);

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
            char timeStr[20];
            if (std::strftime(timeStr, sizeof(timeStr), "%d.%m.%Y %H:%M:%S", &tmBuf)) {
                dateStr = timeStr;
            }
        }
    }
    catch (...) {
        dateStr = "неизвестна";
    }

    reportLines.push_back("Формат: " + format);
    reportLines.push_back("Размер: " + std::to_string(fileSize) + " байт");
    reportLines.push_back("Дата изменения: " + dateStr);

    std::cout << "========================================\n";
    std::cout << "Анализ файла: " << filePath << "\n";
    std::cout << "Формат: " << format << "\n";
    std::cout << "Размер: " << fileSize << " байт\n";
    std::cout << "Дата изменения: " << dateStr << "\n";

    static const std::vector<std::string> relevant = {
        "JPEG", "PNG", "BMP", "GIF", "TIFF", "PSD", "WEBP", "EMF", "WMF"
    };
    bool isRelevant = false;
    for (const auto& f : relevant) {
        if (format == f) { isRelevant = true; break; }
    }

    bool threatDetected = false;
    if (!isRelevant) {
        reportLines.push_back("Формат не поддерживается для стеганографического анализа.");
        std::cout << "Формат не поддерживается для стеганографического анализа.\n";
    }
    else {
        threatDetected = analyzeBuffer(filePath, format, buffer, reportLines);
    }

    if (threatDetected) {
        std::cout << "Результат: Возможна стеганография!\n";
    }
    else {
        std::cout << "Результат: Стеганография не обнаружена.\n";
    }
    std::cout << "========================================\n";

    return reportLines;
}


std::vector<std::pair<std::string, std::vector<std::string>>> SteganographyChecker::analyzeDirectory(const std::string& dirPath) {
    std::vector<std::pair<std::string, std::vector<std::string>>> allReports;

    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (!entry.is_regular_file()) continue;
        std::string filePath = entry.path().string();
        auto reportLines = analyzeFile(filePath);  // 🔁 используем переопределённую analyzeFile
        allReports.emplace_back(filePath, reportLines);  // ✅ собираем вектор
    }

    return allReports;  // ✅ возвращаем в main.cpp для ReportGenerator
}



bool SteganographyChecker::isLSBRelevantFormat(const std::string& format) const {
    static const std::vector<std::string> lsbFormats = {
        "JPEG", "PNG", "BMP", "GIF", "TIFF", "WEBP", "PSD"
    };
    for (const auto& f : lsbFormats) {
        if (format == f) return true;
    }
    return false;
}

bool SteganographyChecker::performLSBAnalysis(const std::vector<uint8_t>& buffer,
    std::vector<std::string>& reportLines) {
    size_t total = buffer.size();
    if (total == 0) return false;

    long long ones = 0;
    for (uint8_t byte : buffer) {
        if (byte & 1) ones++;
    }
    long long zeros = total - ones;

    double percentOnes = (static_cast<double>(ones) / total) * 100.0;
    double p0 = static_cast<double>(zeros) / total;
    double p1 = static_cast<double>(ones) / total;

    double entropy = 0.0;
    if (p0 > 0.0) entropy -= p0 * std::log2(p0);
    if (p1 > 0.0) entropy -= p1 * std::log2(p1);

    // Запись результатов в отчёт
    reportLines.push_back("- LSB-анализ: 1-битов: " + std::to_string(ones) +
        " из " + std::to_string(total) + " (" +
        std::to_string(percentOnes) + "%)");
    reportLines.push_back("- Энтропия LSB: " + std::to_string(entropy) + " бит");

    std::cout << "- LSB-анализ: 1-битов: " << ones << " из " << total << " (" << percentOnes << "%)\n";
    std::cout << "- Энтропия LSB: " << entropy << " бит\n";

    // Пороговые значения для аномалий
    bool percentAnomaly = (percentOnes < 48.0) || (percentOnes > 49.5);
    bool entropyAnomaly = (entropy < 0.98);

    if (percentAnomaly || entropyAnomaly) {
        reportLines.push_back("- [!] Обнаружены аномальные значения LSB: возможная стеганография");
        std::cout << "- [!] Обнаружены аномальные значения LSB: возможная стеганография\n";
        return true; // Аномалия найдена
    }
    return false; // Всё нормально
}

bool SteganographyChecker::analyzeBuffer(const std::string& filePath,
    const std::string& format,
    const std::vector<uint8_t>& buffer,
    std::vector<std::string>& reportLines) {
    bool anomalyDetected = false;

    if (format == "JPEG") {
        if (buffer.size() < 2 || buffer[0] != 0xFF || buffer[1] != 0xD8) {
            std::string line = "- JPEG: неверный или отсутствующий заголовок JPEG.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            size_t eoiPos = 0;
            bool foundEOI = false;
            size_t pos = 2; // После SOI

            while (pos + 3 < buffer.size()) {
                if (buffer[pos] != 0xFF) {
                    pos++;
                    continue;
                }

                uint8_t marker = buffer[pos + 1];
                // EOI
                if (marker == 0xD9) {
                    eoiPos = pos + 2;
                    foundEOI = true;
                    break;
                }

                // Некоторые сегменты без длины (RSTn, SOI, EOI) пропускаем
                if (marker >= 0xD0 && marker <= 0xD7) {
                    pos += 2;
                    continue;
                }

                // Иначе читаем длину сегмента
                if (pos + 4 > buffer.size()) break; // Ошибка
                uint16_t length = (uint16_t(buffer[pos + 2]) << 8) | uint16_t(buffer[pos + 3]);

                // Проверка на APPn или COM сегменты
                if ((marker >= 0xE0 && marker <= 0xEF) || marker == 0xFE) {
                    std::string segType = (marker == 0xFE) ? "COM" : ("APP" + std::to_string(marker - 0xE0));
                    if (length > 2048) { // Порог: 2 КБ для текстовых сегментов
                        std::string line = "- JPEG: подозрительно большой сегмент " + segType + " (" + std::to_string(length) + " байт)";
                        reportLines.push_back(line);
                        std::cout << line << "\n";
                        anomalyDetected = true;
                    }

                    // Специально для APP1 (EXIF)
                    if (marker == 0xE1 && pos + 10 < buffer.size()) {
                        std::string header((const char*)&buffer[pos + 4], 6);
                        if (header != "Exif\0\0") {
                            std::string line = "- JPEG: APP1 сегмент не содержит правильного заголовка EXIF.";
                            reportLines.push_back(line);
                            std::cout << line << "\n";
                            anomalyDetected = true;
                        }
                    }
                }

                if (length < 2) break; // Ошибка длины
                pos += length + 2;
            }

            if (foundEOI && eoiPos < buffer.size()) {
                size_t extra = buffer.size() - eoiPos;
                std::string line = "- JPEG: обнаружены дополнительные данные после EOI: " + std::to_string(extra) + " байт";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
        }
    }

    else if (format == "PNG") {
        if (buffer.size() < 8 || buffer[0] != 0x89 || buffer[1] != 0x50 || buffer[2] != 0x4E || buffer[3] != 0x47) {
            std::string line = "- PNG: неверная сигнатура файла.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            bool foundIEND = false;
            size_t index = 8;
            size_t fileSizeBuf = buffer.size();
            static const std::vector<std::string> standardChunks = {
                "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt",
                "pHYs", "gAMA", "cHRM", "sRGB", "bKGD", "hIST", "iCCP", "sBIT", "tIME", "tRNS"
            };

            while (index + 8 <= fileSizeBuf) {
                uint32_t length = (uint32_t(buffer[index]) << 24) |
                    (uint32_t(buffer[index + 1]) << 16) |
                    (uint32_t(buffer[index + 2]) << 8) |
                    (uint32_t(buffer[index + 3]));

                std::string chunkType((const char*)&buffer[index + 4], 4);
                index += 8;

                bool isStandard = false;
                for (const auto& stdChunk : standardChunks) {
                    if (chunkType == stdChunk) {
                        isStandard = true;
                        break;
                    }
                }

                if (!isStandard) {
                    std::string line = "- PNG: обнаружен нестандартный чанк: " + chunkType;
                    reportLines.push_back(line);
                    std::cout << line << "\n";
                    anomalyDetected = true;
                }

                if (chunkType == "tEXt" || chunkType == "iTXt" || chunkType == "zTXt") {
                    if (index + length > buffer.size()) break; // Защита от выхода за границы
                    const uint8_t* chunkData = &buffer[index];

                    // Проверка размера текстового чанка
                    if (length > 2048) { // Порог: 2 КБ
                        std::string line = "- PNG: слишком большой размер текстового чанка " + chunkType + " (" + std::to_string(length) + " байт)";
                        reportLines.push_back(line);
                        std::cout << line << "\n";
                        anomalyDetected = true;
                    }

                    // Проверка наличия разделителя '\0' (для tEXt и iTXt)
                    if (chunkType == "tEXt" || chunkType == "iTXt") {
                        bool hasNullSeparator = false;
                        for (uint32_t i = 0; i < length; ++i) {
                            if (chunkData[i] == 0) {
                                hasNullSeparator = true;
                                break;
                            }
                        }
                        if (!hasNullSeparator) {
                            std::string line = "- PNG: некорректная структура данных в текстовом чанке " + chunkType + " (нет разделителя '\\0')";
                            reportLines.push_back(line);
                            std::cout << line << "\n";
                            anomalyDetected = true;
                        }
                    }
                }

                if (chunkType == "IEND") {
                    foundIEND = true;
                    size_t endPos = index + length + 4;
                    if (endPos > fileSizeBuf) endPos = fileSizeBuf;
                    if (endPos < fileSizeBuf) {
                        size_t extra = fileSizeBuf - endPos;
                        std::string line = "- PNG: обнаружены данные после IEND: " + std::to_string(extra) + " байт";
                        reportLines.push_back(line);
                        std::cout << line << "\n";
                        anomalyDetected = true;
                    }
                    break;
                }

                if (index + length + 4 > fileSizeBuf) break;
                index += length + 4;
            }

            if (!foundIEND) {
                std::string line = "- PNG: IEND не найден, файл может быть повреждён.";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
        }
    }
    else if (format == "BMP") {
        if (buffer.size() < 6 || buffer[0] != 'B' || buffer[1] != 'M') {
            std::string line = "- BMP: неверный или повреждённый заголовок.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            uint32_t headerSize = (uint32_t)buffer[2] |
                ((uint32_t)buffer[3] << 8) |
                ((uint32_t)buffer[4] << 16) |
                ((uint32_t)buffer[5] << 24);
            uintmax_t actualSize = buffer.size();
            if (actualSize > headerSize) {
                uintmax_t extra = actualSize - headerSize;
                std::string line = "- BMP: обнаружены дополнительные данные: " + std::to_string(extra) + " байт";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
        }
    }
    else if (format == "GIF") {
        if (buffer.size() < 6) {
            std::string line = "- GIF: файл слишком мал.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            std::string header((const char*)buffer.data(), 6);
            if (header != "GIF89a" && header != "GIF87a") {
                std::string line = "- GIF: неподдерживаемый или повреждённый заголовок.";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
            if (buffer.empty() || buffer.back() != 0x3B) {
                std::string line = "- GIF: отсутствует трейлер (0x3B) — возможно, файл обрезан.";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
        }
    }
    else if (format == "TIFF") {
        if (buffer.size() < 4) {
            std::string line = "- TIFF: файл слишком мал или повреждён.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            bool validHeader = ((buffer[0] == 'I' && buffer[1] == 'I' && buffer[2] == 0x2A && buffer[3] == 0x00) ||
                (buffer[0] == 'M' && buffer[1] == 'M' && buffer[2] == 0x00 && buffer[3] == 0x2A));
            if (!validHeader) {
                std::string line = "- TIFF: неверная сигнатура TIFF.";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
            if (buffer.size() > 50ULL * 1024ULL * 1024ULL) {
                std::string line = "- TIFF: подозрительно большой размер (" + std::to_string(buffer.size()) + " байт), возможна стеганография.";
                reportLines.push_back(line);
                std::cout << line << "\n";
                anomalyDetected = true;
            }
        }
    }
    else if (format == "PSD") {
        if (buffer.size() < 4 || std::string((const char*)buffer.data(), 4) != "8BPS") {
            std::string line = "- PSD: повреждённый или неподдерживаемый заголовок.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        if (buffer.size() > 100ULL * 1024ULL * 1024ULL) {
            std::string line = "- PSD: необычно большой размер файла, возможна стеганография.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
    }
    else if (format == "WEBP") {
        if (buffer.size() < 12 || std::string((const char*)buffer.data(), 4) != "RIFF" || std::string((const char*)buffer.data() + 8, 4) != "WEBP") {
            std::string line = "- WebP: неверная структура заголовка RIFF/WEBP.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            size_t i = 12;
            while (i + 8 <= buffer.size()) {
                std::string chunkID((const char*)&buffer[i], 4);
                uint32_t chunkSize = (uint32_t)buffer[i + 4] |
                    ((uint32_t)buffer[i + 5] << 8) |
                    ((uint32_t)buffer[i + 6] << 16) |
                    ((uint32_t)buffer[i + 7] << 24);
                if (!(chunkID == "VP8 " || chunkID == "VP8L" || chunkID == "VP8X" ||
                    chunkID == "ALPH" || chunkID == "ANIM" || chunkID == "ANMF")) {
                    std::string line = "- WebP: обнаружен нестандартный chunk: " + chunkID;
                    reportLines.push_back(line);
                    std::cout << line << "\n";
                    anomalyDetected = true;
                }
                i += 8 + chunkSize;
                if (chunkSize % 2 == 1) i += 1;
            }
        }
    }
    else if (format == "EMF" || format == "WMF") {
        if (buffer.size() < 44) {
            std::string line = "- EMF/WMF: файл слишком мал для анализа.";
            reportLines.push_back(line);
            std::cout << line << "\n";
            anomalyDetected = true;
        }
        else {
            bool isEMF = false;
            if (buffer[40] == 0x20 && buffer[41] == 0x45 && buffer[42] == 0x4D && buffer[43] == 0x46) {
                isEMF = true;
            }
            std::string fmt = isEMF ? "EMF" : "WMF";
            std::string line = "- Определён формат: " + fmt;
            reportLines.push_back(line);
            std::cout << line << "\n";

            if (isEMF) {
                uint32_t declaredSize = (uint32_t)buffer[4] |
                    ((uint32_t)buffer[5] << 8) |
                    ((uint32_t)buffer[6] << 16) |
                    ((uint32_t)buffer[7] << 24);
                size_t expectedBytes = declaredSize * 4ULL;
                if (expectedBytes < buffer.size()) {
                    size_t extra = buffer.size() - expectedBytes;
                    std::string extraLine = "- Обнаружены дополнительные данные после EMF: " + std::to_string(extra) + " байт";
                    reportLines.push_back(extraLine);
                    std::cout << extraLine << "\n";
                    anomalyDetected = true;
                }
            }
        }
    }

    if (isLSBRelevantFormat(format)) {
        bool lsbAnomaly = performLSBAnalysis(buffer, reportLines);
        if (lsbAnomaly) {
            anomalyDetected = true;
        }
    }

    return anomalyDetected;
}
