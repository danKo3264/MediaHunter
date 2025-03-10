#ifndef FILE_READER_H
#define FILE_READER_H

#include <iostream>    // ��� ������ ������ � ���������
#include <fstream>     // ��� ������ � ������� (ifstream)
#include <vector>      // ��� �������� �������� ������ �����
#include <string>      // ��� ������ �� ��������
#include <unordered_map> // ��� �������� �������� ������

using namespace std;

// ����� FileReader �������� �� ������ ������ � ����������� �� ���� �� "magic bytes"
class FileReader {
public:
    // ����������� ��������� ���� � ����� � ���� ������
    explicit FileReader(const string& filePath);

    // ������� loadFile ��������� ���������� ����� � �������� ������ buffer
    // ���������� true, ���� ���� ������� ��������, ����� false
    bool loadFile(vector<uint8_t>& buffer);

    // ������� detectFileType ����������� ������ ����� ����� (magic bytes)
    // � ���������� ��� ����� (��������, \"JPEG\", \"PNG\", \"PDF\", � �.�.)
    string detectFileType(const vector<uint8_t>& buffer);

private:
    // ������ ���� � �����, ������� ����� ���������
    string filePath;
};

#endif // FILE_READER_H
