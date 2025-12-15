#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>  // ДОБАВИТЬ ЭТУ СТРОКУ!

using namespace CryptoPP;

// Функция для генерации ключа и IV из пароля
void DeriveKeyAndIV(const std::string& password, 
                    byte* key, byte* iv, 
                    size_t keyLength, size_t ivLength) {
    
    byte salt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    // Генерируем ключ из пароля
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    pbkdf.DeriveKey(key, keyLength, 0, 
                   (byte*)password.data(), password.size(),
                   salt, sizeof(salt), 1000);
    
    // Генерируем IV из пароля (другой соль)
    byte salt2[] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    pbkdf.DeriveKey(iv, ivLength, 0,
                   (byte*)password.data(), password.size(),
                   salt2, sizeof(salt2), 1000);
}

// Функция шифрования
void EncryptFile(const std::string& inputFile, 
                const std::string& outputFile,
                const std::string& password) {
    
    try {
        // Генерация ключа и IV
        const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;
        const int IV_SIZE = AES::BLOCKSIZE;
        
        byte key[KEY_SIZE];
        byte iv[IV_SIZE];
        
        DeriveKeyAndIV(password, key, iv, KEY_SIZE, IV_SIZE);
        
        // Настройка шифрования AES-CBC
        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);
        
        // Шифрование файла - ИСПРАВЛЕННЫЙ СИНТАКСИС
        FileSource(inputFile.c_str(), true,
            new StreamTransformationFilter(encryptor,
                new FileSink(outputFile.c_str())
            )
        );
        
        std::cout << "Файл успешно зашифрован: " << outputFile << std::endl;
        
        // Выводим IV для отладки (опционально)
        std::string ivHex;
        StringSource(iv, IV_SIZE, true,
            new HexEncoder(
                new StringSink(ivHex)
            )
        );
        std::cout << "IV (hex): " << ivHex << std::endl;
        
    } catch(const Exception& e) {
        std::cerr << "Ошибка при шифровании: " << e.what() << std::endl;
        throw;
    }
}

// Функция расшифрования
void DecryptFile(const std::string& inputFile,
                const std::string& outputFile,
                const std::string& password) {
    
    try {
        // Генерация ключа и IV (таких же, как при шифровании)
        const int KEY_SIZE = AES::DEFAULT_KEYLENGTH;
        const int IV_SIZE = AES::BLOCKSIZE;
        
        byte key[KEY_SIZE];
        byte iv[IV_SIZE];
        
        DeriveKeyAndIV(password, key, iv, KEY_SIZE, IV_SIZE);
        
        // Настройка расшифрования AES-CBC
        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, KEY_SIZE, iv, IV_SIZE);
        
        // Расшифрование файла - ИСПРАВЛЕННЫЙ СИНТАКСИС
        FileSource(inputFile.c_str(), true,
            new StreamTransformationFilter(decryptor,
                new FileSink(outputFile.c_str())
            )
        );
        
        std::cout << "Файл успешно расшифрован: " << outputFile << std::endl;
        
        // Показать содержимое расшифрованного файла
        std::ifstream decryptedFile(outputFile);
        std::string content((std::istreambuf_iterator<char>(decryptedFile)),
                           std::istreambuf_iterator<char>());
        std::cout << "Содержимое: " << content << std::endl;
        
    } catch(const Exception& e) {
        std::cerr << "Ошибка при расшифровании: " << e.what() << std::endl;
        throw;
    }
}

int main(int argc, char* argv[]) {
    // Устанавливаем локаль для поддержки русского текста
    std::locale::global(std::locale(""));
    
    // Проверяем аргументы
    if (argc != 5) {
        std::cerr << "Использование:" << std::endl;
        std::cerr << "  Шифрование: " << argv[0] << " -e <входной файл> <выходной файл> <пароль>" << std::endl;
        std::cerr << "  Расшифрование: " << argv[0] << " -d <входной файл> <выходной файл> <пароль>" << std::endl;
        return 1;
    }
    
    std::string mode = argv[1];
    std::string inputFile = argv[2];
    std::string outputFile = argv[3];
    std::string password = argv[4];
    
    try {
        if (mode == "-e") {
            EncryptFile(inputFile, outputFile, password);
        } else if (mode == "-d") {
            DecryptFile(inputFile, outputFile, password);
        } else {
            std::cerr << "Неверный режим. Используйте -e для шифрования или -d для расшифрования." << std::endl;
            return 1;
        }
    } catch(...) {
        return 1;
    }
    
    return 0;
}
