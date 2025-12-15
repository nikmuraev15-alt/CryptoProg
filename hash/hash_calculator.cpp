#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

int main(int argc, char* argv[]) {
    // Проверяем аргументы командной строки
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <имя файла>" << std::endl;
        return 1;
    }

    std::string filename = argv[1];
    
    try {
        // Создаем объект SHA-256
        SHA256 hash;
        std::string digest;
        
        // Читаем файл и вычисляем хеш
        FileSource(filename.c_str(), true, 
                   new HashFilter(hash,
                       new HexEncoder(
                           new StringSink(digest)
                       )
                   )
               );
        
        // Выводим результат
        std::cout << "SHA-256: " << digest << std::endl;
        
        // Сравниваем с sha256sum (опционально)
        std::cout << "\nДля проверки выполните команду:" << std::endl;
        std::cout << "sha256sum " << filename << std::endl;
        
    } catch(const Exception& e) {
        std::cerr << "Ошибка: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
