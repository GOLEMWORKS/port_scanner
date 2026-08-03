CXX = clang++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS =

TARGET = scanner_demo
SRC = port_scanner.cpp main.cpp
OBJ = $(SRC:.cpp=.o)

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET)
