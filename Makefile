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
	$(CXX) -o payment_in_out_generate_keypair.o src/payment_in_out_generate_keypair.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_generate_keypair payment_in_out_generate_keypair.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_in_out_generate_proof.o src/payment_in_out_generate_proof.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_generate_proof payment_in_out_generate_proof.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_in_out_verify_proof.o src/payment_in_out_verify_proof.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_in_out_verify_proof payment_in_out_verify_proof.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_multi_generate_keypair.o src/payment_multi_generate_keypair.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_multi_generate_keypair payment_multi_generate_keypair.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_multi_generate_proof.o src/payment_multi_generate_proof.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_multi_generate_proof payment_multi_generate_proof.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CXX) -o payment_multi_verify_proof.o src/payment_multi_verify_proof.cpp -c $(CXXFLAGS) $(LIBSNARK_FLAGS) $(OPTFLAGS)
	$(CXX) -o payment_multi_verify_proof payment_multi_verify_proof.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) test.o test
