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
	@echo "=== Тестирование шифрования/расшифрования ==="
	@echo "1. Создаем тестовый файл..."
	@echo -n "Секрет." > test.txt
	@echo "2. Шифруем файл..."
	@./$(TARGET) encrypt test.txt test.enc "mypassword123"
	@echo "3. Расшифровываем файл..."
	@./$(TARGET) decrypt test.enc test_dec.txt "mypassword123"
	@echo "4. Сравниваем оригинал и расшифрованный файл..."
	@cmp -s test.txt test_dec.txt && echo "✓ Файлы идентичны! Тест пройден." || echo "✗ Ошибка: файлы различаются!"
	@echo "5. Оригинальный файл:"
	@cat test.txt
	@echo "6. Расшифрованный файл:"
	@cat test_dec.txt
	@rm -f test.enc test_dec.txt

.PHONY: all clean test
