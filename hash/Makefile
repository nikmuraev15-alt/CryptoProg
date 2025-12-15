CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2
LDFLAGS = -lcryptopp

TARGET = hash_calculator
SOURCES = hash_calculator.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

test: $(TARGET)
	./$(TARGET) test.txt

.PHONY: all clean test
