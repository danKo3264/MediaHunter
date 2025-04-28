#ifndef FILE_READER_H
#define FILE_READER_H

#include <string>
#include <vector>
#include <cstdint>

// Простое чтение произвольного файла в память + определение типа по magic‑bytes
class FileReader {
public:
    explicit FileReader(const std::string& filePath);
    bool loadFile(std::vector<uint8_t>& buffer);               // загрузить весь файл в buffer
    std::string detectFileType(const std::vector<uint8_t>& buffer) const; // определить тип

private:
    std::string filePath_;
};

#endif // FILE_READER_H
