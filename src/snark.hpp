#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libff/common/utils.hpp"
#include <boost/optional.hpp>

using namespace libsnark;
using namespace std;

#include "gadget.hpp"

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair()
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   const bit_vector &h1,
                                                                   const bit_vector &h2,
                                                                   const bit_vector &h3,
                                                                   const bit_vector &r1,
                                                                   const bit_vector &r2,
                                                                   const bit_vector &r3
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(h1, h2, h3, r1, r2, r3);

    if (!pb.is_satisfied()) {
      std::cout << "System not satisfied!" << std::endl;
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const bit_vector &h1,
                  const bit_vector &h2,
                  const bit_vector &h3
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1, h2, h3);

    std::cout << "**** After l_input_map *****" << std::endl;

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);

}
