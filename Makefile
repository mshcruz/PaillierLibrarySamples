COMPILER = $(CXX)
CPPFLAGS = -Wall -std=c++11
LIBS = -lgmp #-lpaillier
OBJS = paillier.o
ADDITIONAL_FILES = pubkey.txt seckey.txt ciphertext1.txt ciphertext2.txt
TARGET = encryptedSum encryptionDecryption createExportKeys createExportCtxts importCtxtsSum

.PHONY: all clean run

all: $(TARGET)

encryptedSum: encryptedSum.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

encryptionDecryption: encryptionDecryption.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

exportImportKeysCtxts: exportImportKeysCtxts.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

createExportKeys: createExportKeys.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

createExportCtxts: createExportCtxts.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

importCtxtsSum: importCtxtsSum.cpp $(OBJS)
	$(COMPILER) $(CPPFLAGS) $(OBJS) $< -o $@ $(LIBS)

paillier.o: paillier.c paillier.h 
	$(COMPILER) $(CPPFLAGS) $< -c

# run: $(TARGET)
# 	./$(TARGET)

clean:
	rm -rf $(TARGET) $(OBJS) $(ADDITIONAL_FILES)
