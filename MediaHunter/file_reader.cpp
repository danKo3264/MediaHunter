#include "file_reader.h"  // Подключаем заголовочный файл с объявлением класса
#include <fstream>        // Для работы с файлами
#include <algorithm>      // Для функции std::equal

// Конструктор класса, сохраняющий путь к файлу
FileReader::FileReader(const string& filePath) : filePath(filePath) {}

// Функция loadFile загружает содержимое файла в бинарный вектор buffer
bool FileReader::loadFile(vector<uint8_t>& buffer) {
    // Открываем файл в бинарном режиме
    ifstream file(filePath, ios::binary);
    if (!file) {
        cerr << "Ошибка: не удалось открыть файл: " << filePath << endl;
        return false;
    }

    // Определяем размер файла
    file.seekg(0, ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);

    // Изменяем размер вектора для хранения всех данных файла
    buffer.resize(fileSize);

    // Читаем данные файла в буфер
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    return true;
}

// Функция detectFileType анализирует первые байты (magic bytes) файла
// и пытается определить тип файла по известным сигнатурам.
// Из списка удалён PDF, так как он не считается медиа-файлом.
string FileReader::detectFileType(const vector<uint8_t>& buffer) {
    // Если размер буфера слишком маленький, определить тип невозможно
    if (buffer.size() < 4)
        return "Unknown";

    // Список известных сигнатур файлов с соответствующими magic bytes
    unordered_map<string, vector<uint8_t>> signatures = {
        {"JPEG", {0xFF, 0xD8, 0xFF}},
        {"PNG",  {0x89, 0x50, 0x4E, 0x47}},
        {"MP4",  {0x66, 0x74, 0x79, 0x70}},
        {"MP3",  {0x49, 0x44, 0x33}}  // ID3 тег MP3
    };

    // Проходим по списку сигнатур и проверяем, соответствует ли начало файла одной из них
    for (const auto& [type, signature] : signatures) {
        if (buffer.size() >= signature.size() && equal(signature.begin(), signature.end(), buffer.begin())) {
            return type;
        }
    }
    return "Unknown";
}
