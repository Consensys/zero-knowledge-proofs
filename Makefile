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
	$(CXX) -o payment_in_out_keypair_generator.o src/payment_in_out_keypair_generator.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_keypair_generator payment_in_out_keypair_generator.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_in_out_proof_generator.o src/payment_in_out_proof_generator.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_proof_generator payment_in_out_proof_generator.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_in_out_proof_verifier.o src/payment_in_out_proof_verifier.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_proof_verifier payment_in_out_proof_verifier.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
#	$(CXX) -o test.o src/test.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
#	$(CXX) -o test test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) test.o test
