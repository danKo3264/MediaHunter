#ifndef FILE_READER_H
#define FILE_READER_H

#include <iostream>    // Для вывода ошибок и сообщений
#include <fstream>     // Для работы с файлами (ifstream)
#include <vector>      // Для хранения бинарных данных файла
#include <string>      // Для работы со строками
#include <unordered_map> // Для хранения сигнатур файлов

using namespace std;

// Класс FileReader отвечает за чтение файлов и определение их типа по "magic bytes"
class FileReader {
public:
    // Конструктор принимает путь к файлу в виде строки
    explicit FileReader(const string& filePath);

    // Функция loadFile загружает содержимое файла в бинарный вектор buffer
    // Возвращает true, если файл успешно прочитан, иначе false
    bool loadFile(vector<uint8_t>& buffer);

    // Функция detectFileType анализирует первые байты файла (magic bytes)
    // и возвращает тип файла (например, \"JPEG\", \"PNG\", \"PDF\", и т.д.)
    string detectFileType(const vector<uint8_t>& buffer);

private:
    // Хранит путь к файлу, который нужно прочитать
    string filePath;
};

#endif // FILE_READER_H
