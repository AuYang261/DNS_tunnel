DEBUG := -g
SRC = $(wildcard ./*.cpp)
TARGET = main
BIN = bin/
INC = ./


build: ${SRC}
	g++ ${SRC} -lpcap -o ${BIN}${TARGET} -I ${INC}

build-debug: ${SRC}
	g++ ${SRC} -lpcap -o ${BIN}${TARGET} -I ${INC} $(DEBUG)

all: run

run: build 
	./${BIN}${TARGET}

debug: build-debug
	gdbserver :1234 ./${BIN}${TARGET}

clean:
	rm -rf ${BIN}${TARGET}
	