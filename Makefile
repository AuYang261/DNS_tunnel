DEBUG := -g
SRC = main.cpp
TARGET = main
BIN = bin/


build:
	g++ ${SRC} -lpcap -o ${BIN}${TARGET}

build-debug:
	g++ ${SRC} -lpcap -o ${BIN}${TARGET} $(DEBUG)

all: run

run: build 
	./${BIN}${TARGET}

debug: build-debug
	gdbserver :1234 ./${BIN}${TARGET}