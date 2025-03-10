#include "file_reader.h"  // ���������� ������������ ���� � ����������� ������
#include <fstream>        // ��� ������ � �������
#include <algorithm>      // ��� ������� std::equal

// ����������� ������, ����������� ���� � �����
FileReader::FileReader(const string& filePath) : filePath(filePath) {}

// ������� loadFile ��������� ���������� ����� � �������� ������ buffer
bool FileReader::loadFile(vector<uint8_t>& buffer) {
    // ��������� ���� � �������� ������
    ifstream file(filePath, ios::binary);
    if (!file) {
        cerr << "������: �� ������� ������� ����: " << filePath << endl;
        return false;
    }

    // ���������� ������ �����
    file.seekg(0, ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);

    // �������� ������ ������� ��� �������� ���� ������ �����
    buffer.resize(fileSize);

    // ������ ������ ����� � �����
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    file.close();

    return true;
}

// ������� detectFileType ����������� ������ ����� (magic bytes) �����
// � �������� ���������� ��� ����� �� ��������� ����������.
// �� ������ ����� PDF, ��� ��� �� �� ��������� �����-������.
string FileReader::detectFileType(const vector<uint8_t>& buffer) {
    // ���� ������ ������ ������� ���������, ���������� ��� ����������
    if (buffer.size() < 4)
        return "Unknown";

    // ������ ��������� �������� ������ � ���������������� magic bytes
    unordered_map<string, vector<uint8_t>> signatures = {
        {"JPEG", {0xFF, 0xD8, 0xFF}},
        {"PNG",  {0x89, 0x50, 0x4E, 0x47}},
        {"MP4",  {0x66, 0x74, 0x79, 0x70}},
        {"MP3",  {0x49, 0x44, 0x33}}  // ID3 ��� MP3
    };

    // �������� �� ������ �������� � ���������, ������������� �� ������ ����� ����� �� ���
    for (const auto& [type, signature] : signatures) {
        if (buffer.size() >= signature.size() && equal(signature.begin(), signature.end(), buffer.begin())) {
            return type;
        }
    }
    return "Unknown";
}
