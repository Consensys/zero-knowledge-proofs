OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
#CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128
CXXFLAGS += -I/usr/local/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128 -DWITH_PROCPS=OFF
CXXFLAGS += -I/usr/local/include/libff
CXXFLAGS += -I/usr/local/include/libfqfft
LDFLAGS += -flto

#DEPSRC=depsrc
#DEPINST=depinst

#LDLIBS += -L $(DEPINST)/lib -Wl,-rpath $(DEPINST)/lib -L . -lsnark -lgmpxx -lgmp
LDLIBS += -L/usr/local/lib/ -lsnark -lff -lgmpxx -lgmp
LDLIBS += -lboost_system

all:
	$(CXX) -o test.o src/test.cpp -c $(CXXFLAGS)
	$(CXX) -o test test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) test.o test
