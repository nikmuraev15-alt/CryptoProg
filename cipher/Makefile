CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS = -lcryptopp

TARGET = file_cipher
SOURCES = file_cipher.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) *.enc *.dec

test: $(TARGET)
	@echo "Тестирование шифрования/расшифрования..."
	@echo "Создаем тестовый файл..."
	@echo "Hello, Crypto++! This is a test file." > test.txt
	@echo "Шифруем..."
	@./$(TARGET) -e test.txt test.enc "mysecretpassword"
	@echo "Расшифровываем..."
	@./$(TARGET) -d test.enc test.dec "mysecretpassword"
	@echo "Сравниваем оригинал и расшифрованный файл..."
	@cmp -s test.txt test.dec && echo "✓ Файлы идентичны!" || echo "✗ Ошибка: файлы различаются!"
	@rm -f test.txt test.enc test.dec

.PHONY: all clean test
