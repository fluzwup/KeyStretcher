
BASEDIR = .

BINARY = pwfile

CPPSOURCES = main.cpp CryptKeeper.cpp CryptKeeperDES.cpp DES.cpp misc.cpp CryptKeeperPW.cpp

OBJECTS = ${CPPSOURCES:.cpp=.o} 

INCLUDES = -I .  -I /usr/include 

LOCATIONS =  -L/usr/local/lib  -L/usr/lib 

LIBRARIES =  -lcrypto
CXXFLAGS = -ggdb  

CXX = g++ ${CXXFLAGS} -DREENTRANT -D_REENTRANT 

.SUFFIXES:      .cpp .o

.cpp.o:
		@echo
		@echo Building $@
		${CXX} ${INCLUDES} -c -o $@ $<          

all:            ${OBJECTS} ${BINARY} 

${BINARY}:      ${OBJECTS}
		@echo
		@echo Building ${BINARY} Executable
		${CXX} -o $@ \
		${OBJECTS}  \
		${LIBRARIES} \
		${LOCATIONS}
                         
clean:
		rm -f ${BINARY} *.o



