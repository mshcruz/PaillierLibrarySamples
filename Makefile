COMPILER = $(CXX)
CPPFLAGS = -Wall -std=c++11
LIBS = -lgmp #-lpaillier
OBJS = paillier.o
ADDITIONAL_FILES = pubkey.txt seckey.txt ciphertext1.txt ciphertext2.txt
TARGET=$(patsubst %.cpp, %, $(wildcard *.cpp))

.PHONY: all clean run

all: $(TARGET)

paillier.o: paillier.c paillier.h 
	$(COMPILER) $(CPPFLAGS) $< -c

%: %.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

clean:
	rm -rf $(TARGET) $(OBJS) $(ADDITIONAL_FILES)
