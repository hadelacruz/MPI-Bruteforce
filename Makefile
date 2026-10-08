# Makefile - Proyecto 2 (Bruteforce DES con MPI)
# Compila los fuentes de src/ y deja los ejecutables en bin/.
# Requiere gcc y Open MPI (mpicc). Pensado para Linux / WSL.

CC     = gcc
MPICC  = mpicc
CFLAGS = -O2 -Wall
SRC    = src
BIN    = bin

# Programas secuenciales / utilidades (no necesitan MPI)
SEQ = $(BIN)/test_des $(BIN)/cifrar $(BIN)/secuencial
# Programas paralelos (necesitan MPI)
PAR = $(BIN)/bruteforce $(BIN)/cyclic $(BIN)/master_worker

all: $(SEQ) $(PAR)

$(BIN):
	mkdir -p $(BIN)

$(BIN)/test_des: $(SRC)/test_des.c $(SRC)/des.c | $(BIN)
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $^

$(BIN)/cifrar: $(SRC)/cifrar.c $(SRC)/des.c $(SRC)/keyutil.c | $(BIN)
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $^

$(BIN)/secuencial: $(SRC)/secuencial.c $(SRC)/des.c $(SRC)/keyutil.c | $(BIN)
	$(CC) $(CFLAGS) -I$(SRC) -o $@ $^

$(BIN)/bruteforce: $(SRC)/bruteforce.c $(SRC)/des.c $(SRC)/keyutil.c | $(BIN)
	$(MPICC) $(CFLAGS) -I$(SRC) -o $@ $^

$(BIN)/cyclic: $(SRC)/cyclic.c $(SRC)/des.c $(SRC)/keyutil.c | $(BIN)
	$(MPICC) $(CFLAGS) -I$(SRC) -o $@ $^

$(BIN)/master_worker: $(SRC)/master_worker.c $(SRC)/des.c $(SRC)/keyutil.c | $(BIN)
	$(MPICC) $(CFLAGS) -I$(SRC) -o $@ $^

clean:
	rm -rf $(BIN)

.PHONY: all clean
