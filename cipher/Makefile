CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS = -lcryptopp

TARGET = file_cipher
SOURCES = file_cipher.cpp  # УБРАТЬ ПРОБЕЛ!
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
	@echo "1. Создаем тестовый файл с русским текстом..."
	@echo -n "Секрет." > test.txt
	@echo "2. Шифруем файл..."
	@./$(TARGET) -e test.txt test.enc "пароль123"
	@echo "3. Расшифровываем файл..."
	@./$(TARGET) -d test.enc test.dec "пароль123"
	@echo "4. Сравниваем оригинал и расшифрованный файл..."
	@cmp -s test.txt test.dec && echo "✓ Файлы идентичны! Тест пройден." || echo "✗ Ошибка: файлы различаются!"
	@echo "5. Оригинальный файл:"
	@cat test.txt
	@echo "6. Расшифрованный файл:"
	@cat test.dec
	@rm -f test.enc test.dec

.PHONY: all clean test
