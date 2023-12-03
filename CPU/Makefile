G++ = g++
CPP_FLAGS = -O2 -std=c++17
SRC_DIR = ./src
INCLUDE_DIR = ./include

SOURCE = $(shell find $(SRC_DIR) -path $(SRC_DIR)/main -prune -o -name "*.cpp" -print)
OBJECT = $(SOURCE:$(SRC_DIR)/%.cpp=$(SRC_DIR)/%.o)

all: benchmark

# note: add -lboost_program_options flag if use boost library to parse args
benchmark: $(SRC_DIR)/main/main.cpp $(OBJECT)
	$(G++) -I$(INCLUDE_DIR) $(CPP_FLAGS) -c $(SRC_DIR)/main/main.cpp -o $(SRC_DIR)/main/main.o
	$(G++) $(SRC_DIR)/main/main.o $(OBJECT) $(CPP_FLAGS) -o benchmark

${OBJECT}: %.o:%.cpp
	$(G++) -I$(INCLUDE_DIR) $(CPP_FLAGS) -c $< -o $@

testprint:
	echo $(SOURCE) 
	echo $(OBJECT)

clean:
	find . -name "*.o"  | xargs rm -f
	rm benchmark

.PHONY: clean