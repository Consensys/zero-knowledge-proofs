INSTALLDIR=libsnark/build/install
LIBFQFFT_INSTALLDIR=libsnark/libfqfft/build/install
LIBSNARK_FLAGS= -DUSE_ASM -DCURVE_ALT_BN128 -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF 

OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
CXXFLAGS += -I$(INSTALLDIR)/usr/local/include
CXXFLAGS += -I$(LIBFQFFT_INSTALLDIR)/include
LDFLAGS += -flto

LDLIBS += -L$(INSTALLDIR)/usr/local/lib/ -lsnark -lff -lgmpxx -lgmp
LDLIBS += -lboost_system

all:
	$(CXX) -o test.o src/test.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o test test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) test.o test