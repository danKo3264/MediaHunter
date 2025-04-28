#include "file_reader.h"
#include <fstream>
#include <algorithm>
#include <unordered_map>
#include <iostream>

FileReader::FileReader(const std::string& filePath)
    : filePath_(filePath) {
}

bool FileReader::loadFile(std::vector<uint8_t>& buffer) {
    std::ifstream in(filePath_, std::ios::binary);
    if (!in) {
        std::cerr << "Ошибка: не удалось открыть файл: " << filePath_ << "\n";
        return false;
    }
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (size < 0) size = 0;
    buffer.resize(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(buffer.data()), size);
    return true;
}

std::string FileReader::detectFileType(const std::vector<uint8_t>& buf) const {
    if (buf.size() < 12) return "Unknown";

    struct Magic {
        std::string type;
        std::vector<uint8_t> sig;
        size_t offset;
    };

    std::vector<Magic> signatures = {
        {"JPEG",   {0xFF, 0xD8, 0xFF}, 0},
        {"PNG",    {0x89, 0x50, 0x4E, 0x47}, 0},
        {"BMP",    {0x42, 0x4D}, 0},
        {"MP3",    {0x49, 0x44, 0x33}, 0},
        {"MP4",    {'f', 't', 'y', 'p'}, 4},
        {"WebM",   {'w', 'e', 'b', 'm'}, 31},
        {"MKV",    {0x1A, 0x45, 0xDF, 0xA3}, 0},
        {"PSD",    {0x38, 0x42, 0x50, 0x53}, 0},
        {"HEVC",   {0x00, 0x00, 0x00, 0x01, 0x40}, 0}, // NAL Unit for HEVC
        {"AV1",    {'A', 'V', '1'}, 4},
        {"TIFF",   {0x49, 0x49, 0x2A, 0x00}, 0},
        {"TIFF",   {0x4D, 0x4D, 0x00, 0x2A}, 0},
        {"CR2",    {0x49, 0x49, 0x2A, 0x00, 0x10, 0x00, 0x00, 0x00, 'C', 'R'}, 0},
        {"NEF",    {0x49, 0x49, 0x2A, 0x00}, 0},
        {"DNG",    {0x49, 0x49, 0x2A, 0x00}, 0},
        {"EMF",    {0x01, 0x00, 0x00, 0x00}, 40},
        {"WMF",    {0xD7, 0xCD, 0xC6, 0x9A}, 0},
        {"RIFF",   {'R', 'I', 'F', 'F'}, 0} // Общее распознавание RIFF-файлов (AVI/WebP)
    };

    for (const auto& s : signatures) {
        if (buf.size() >= s.offset + s.sig.size() &&
            std::equal(s.sig.begin(), s.sig.end(), buf.begin() + s.offset)) {
            // Специальная обработка RIFF: отличить WebP от AVI
            if (s.type == "RIFF") {
                if (buf.size() >= 12 && std::equal(buf.begin() + 8, buf.begin() + 12, reinterpret_cast<const uint8_t*>("WEBP"))) {
                    return "WEBP";
                }
                else {
                    return "AVI";
                }
            }
            return s.type;
        }
    }

    return "Unknown";
}

