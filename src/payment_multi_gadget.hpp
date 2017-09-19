#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libff/algebra/fields/field_utils.hpp"
#include <typeinfo>


using namespace libff;

const size_t sha256_digest_len = 256;
const int unsigned noIncomingPayments = 6;   //Note, you must update the variables in the r1 constraint on line 288
const int unsigned noOutgoingPayments = 6;
int unsigned counter;

bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT>
class payment_multi_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */

    pb_variable_array<FieldT> intermediate_startBalance;
    pb_variable_array<FieldT> intermediate_endBalance;
    pb_variable_array<FieldT> intermediate_incoming[noIncomingPayments];
    pb_variable_array<FieldT> intermediate_outgoing[noOutgoingPayments];

    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h_startBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> h_endBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> h_incoming_var[noIncomingPayments]; 
    std::shared_ptr<digest_variable<FieldT>> h_outgoing_var[noOutgoingPayments]; 

    std::shared_ptr<digest_variable<FieldT>> r_startBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> r_endBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> r_incoming_var[noIncomingPayments]; 
    std::shared_ptr<digest_variable<FieldT>> r_outgoing_var[noOutgoingPayments]; 

    std::shared_ptr<block_variable<FieldT>> h_r_startBalance_block; /* 512 bit block that contains startBalance + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_startBalance; /* hashing gadget for startBalance */

    std::shared_ptr<block_variable<FieldT>> h_r_endBalance_block; /* 512 bit block that contains endBalance + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_endBalance; /* hashing gadget for endBalance */

    std::shared_ptr<block_variable<FieldT>> h_r_incoming_block[noIncomingPayments]; /* 512 bit block that contains incoming + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_incoming[noIncomingPayments]; /* hashing gadget for incoming */

    std::shared_ptr<block_variable<FieldT>> h_r_outgoing_block[noOutgoingPayments]; /* 512 bit block that contains outgoing + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_outgoing[noOutgoingPayments]; /* hashing gadget for outgoing */

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */

    payment_multi_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "payment_multi_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * (2 + noIncomingPayments + noOutgoingPayments);   //The 2 are the beforeBalance and the afterBalance
        {
            // We use a "multipacking" technique which allows us to constrain
            // the input bits in as few field elements as possible.
            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());

            std::cout << "**************** input_size_in_field_elements: " << input_size_in_field_elements << "\n";
            std::cout << "**************** FieldT::capacity(): " << FieldT::capacity() << "\n";
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_elements);
        }

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        intermediate_startBalance.allocate(this->pb, sha256_digest_len/2, "intermediate_startBalance");
        intermediate_endBalance.allocate(this->pb, sha256_digest_len/2, "intermediate_endBalance");

        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          intermediate_incoming[counter].allocate(this->pb, sha256_digest_len/2, "intermediate_incoming" + std::to_string(counter+1));
        }

        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          intermediate_outgoing[counter].allocate(this->pb, sha256_digest_len/2, "intermediate_outgoing" + std::to_string(counter+1));
        }

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
          if (sha256_padding[i])
            padding_var.emplace_back(ONE);
          else
            padding_var.emplace_back(zero);
        }

        // Verifier (and prover) inputs:
        h_startBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_startBalance"));
        h_endBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_endBalance"));
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          h_incoming_var[counter].reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_incoming" + std::to_string(counter+1)));
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          h_outgoing_var[counter].reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_outgoing" + std::to_string(counter+1)));
        }

        input_as_bits.insert(input_as_bits.end(), h_startBalance_var->bits.begin(), h_startBalance_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_endBalance_var->bits.begin(), h_endBalance_var->bits.end());
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          input_as_bits.insert(input_as_bits.end(), h_incoming_var[counter]->bits.begin(), h_incoming_var[counter]->bits.end());
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          input_as_bits.insert(input_as_bits.end(), h_outgoing_var[counter]->bits.begin(), h_outgoing_var[counter]->bits.end());
        }

        // Multipacking
            std::cout << "**************** input_size_bits: " << input_size_in_bits << "\n";
            std::cout << "**************** input_as_bits.size(): " << input_as_bits.size() << "\n";
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r_startBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_startBalance"));
        r_endBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_endBalance"));
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          r_incoming_var[counter].reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_incoming" + std::to_string(counter+1)));
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          r_outgoing_var[counter].reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_outgoing" + std::to_string(counter+1)));
        }

        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        h_r_startBalance_block.reset(new block_variable<FieldT>(pb, {
            r_startBalance_var->bits,
            padding_var
        }, "h_r_startBalance_block"));

        h_r_startBalance.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_startBalance_block->bits,
                                                                  *h_startBalance_var,
                                                                  "h_r_startBalance"));

        h_r_endBalance_block.reset(new block_variable<FieldT>(pb, {
            r_endBalance_var->bits,
            padding_var
        }, "h_r_endBalance_block"));

        h_r_endBalance.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_endBalance_block->bits,
                                                                  *h_endBalance_var,
                                                                  "h_r_endBalance"));

        
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          h_r_incoming_block[counter].reset(new block_variable<FieldT>(pb, {
              r_incoming_var[counter]->bits,
              padding_var
          }, "h_r_incoming" + std::to_string(counter+1) + "_block"));

          h_r_incoming[counter].reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                    IV,
                                                                    h_r_incoming_block[counter]->bits,
                                                                    *h_incoming_var[counter],
                                                                    "h_r_incoming" + std::to_string(counter+1)));
        }

        for (counter = 0; counter < noOutgoingPayments; counter++)
        {

          h_r_outgoing_block[counter].reset(new block_variable<FieldT>(pb, {
              r_outgoing_var[counter]->bits,
              padding_var
          }, "h_r_outgoing" + std::to_string(counter+1) + "_block"));

          h_r_outgoing[counter].reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                    IV,
                                                                    h_r_outgoing_block[counter]->bits,
                                                                    *h_outgoing_var[counter],
                                                                    "h_r_outgoing" + std::to_string(counter+1)));
        }
    }

    void generate_payment_multi_constraints()
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r_startBalance_var->generate_r1cs_constraints();
        r_endBalance_var->generate_r1cs_constraints();
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          r_incoming_var[counter]->generate_r1cs_constraints();
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          r_outgoing_var[counter]->generate_r1cs_constraints();
        }

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        unsigned int NN = sha256_digest_len/2;

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_startBalance[0],
                1, 
                r_startBalance_var->bits[0]),
            FMT(this->annotation_prefix, " zero1_%zu", 0));

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_endBalance[0],
                1, 
                r_endBalance_var->bits[0]),
            FMT(this->annotation_prefix, " zero2_%zu", 0));

        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  intermediate_incoming[counter][0],
                  1, 
                  r_incoming_var[counter]->bits[0]),
              FMT(this->annotation_prefix, " zero" + std::to_string(counter+3) + "_%zu", 0));
        }

        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  intermediate_outgoing[counter][0],
                  1, 
                  r_outgoing_var[counter]->bits[0]),
              FMT(this->annotation_prefix, " zero" + std::to_string(counter+3+noIncomingPayments) + "_%zu", 0));
        }

        for (unsigned int i = 1; i < NN; i++) {

          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  { intermediate_startBalance[i] },
                  { ONE },
                { intermediate_startBalance[i-1] * 2 , r_startBalance_var->bits[i] }), 
              FMT(this->annotation_prefix, " sum1_%zu", i));

          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  { intermediate_endBalance[i] },
                  { 1 }, 
                  { intermediate_endBalance[i-1] * 2, r_endBalance_var->bits[i] }), 
              FMT(this->annotation_prefix, " sum2_%zu", i));

          for (counter = 0; counter < noIncomingPayments; counter++)
          {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_incoming[counter][i] },
                    { 1 }, 
                    { intermediate_incoming[counter][i-1] * 2, r_incoming_var[counter]->bits[i] }), 
                FMT(this->annotation_prefix, " sum" + std::to_string(counter+3) + "_%zu", i));
          }

          for (counter = 0; counter < noOutgoingPayments; counter++)
          {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_outgoing[counter][i] },
                    { 1 }, 
                    { intermediate_outgoing[counter][i-1] * 2, r_outgoing_var[counter]->bits[i] }), 
                FMT(this->annotation_prefix, " sum" + std::to_string(counter+3+noIncomingPayments) + "_%zu", i));
          }
        }

        // Constraint that start bal + sum(incoming) = end bal + sum(outgoing)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                { intermediate_startBalance[NN-1], intermediate_incoming[0][NN-1], intermediate_incoming[1][NN-1], intermediate_incoming[2][NN-1], intermediate_incoming[3][NN-1], intermediate_incoming[4][NN-1], intermediate_incoming[5][NN-1]},
                { 1 },
                { intermediate_endBalance[NN-1], intermediate_outgoing[0][NN-1], intermediate_outgoing[1][NN-1], intermediate_outgoing[2][NN-1], intermediate_outgoing[3][NN-1], intermediate_outgoing[4][NN-1], intermediate_outgoing[5][NN-1]}), 
            FMT(this->annotation_prefix, "finalsum_%zu", 0));
        

        // These are the constraints to ensure the hashes validate.
        h_r_startBalance->generate_r1cs_constraints();
        h_r_endBalance->generate_r1cs_constraints();
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          h_r_incoming[counter]->generate_r1cs_constraints();
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          h_r_outgoing[counter]->generate_r1cs_constraints();
        }
    }

    void generate_payment_multi_witness(const bit_vector &h_startBalance,
                               const bit_vector &h_endBalance,
                               const bit_vector *h_incoming,
                               const bit_vector *h_outgoing,
                               const bit_vector &r_startBalance,
                               const bit_vector &r_endBalance,
                               const bit_vector *r_incoming,
                               const bit_vector *r_outgoing
                              )
    {
        // Fill our digests with our witnessed data
        r_startBalance_var->bits.fill_with_bits(this->pb, r_startBalance);
        r_endBalance_var->bits.fill_with_bits(this->pb, r_endBalance);
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          r_incoming_var[counter]->bits.fill_with_bits(this->pb, r_incoming[counter]);
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          r_outgoing_var[counter]->bits.fill_with_bits(this->pb, r_outgoing[counter]);
        }
 
        size_t NN = sha256_digest_len/2;
        
        std::vector<FieldT> interm_startBalance(NN);
        std::vector<FieldT> interm_endBalance(NN);

        std::array<std::vector<FieldT>, noIncomingPayments> interm_incoming;
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          interm_incoming[counter] = std::vector<FieldT>(NN);
        }
        std::array<std::vector<FieldT>, noOutgoingPayments> interm_outgoing;
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          interm_outgoing[counter] = std::vector<FieldT>(NN);
        }

        interm_startBalance[0] = r_startBalance[0] ? FieldT::one() : FieldT::zero();
        interm_endBalance[0] = r_endBalance[0] ? FieldT::one() : FieldT::zero();
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          interm_incoming[counter][0] = r_incoming[counter][0] ? FieldT::one() : FieldT::zero();
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          interm_incoming[counter][0] = r_incoming[counter][0] ? FieldT::one() : FieldT::zero();
        }

        for (size_t i=1; i<NN; i++) {
          interm_startBalance[i] = interm_startBalance[i-1] * 2 + (r_startBalance[i] ? FieldT::one() : FieldT::zero());
          interm_endBalance[i] = interm_endBalance[i-1] * 2 + (r_endBalance[i] ? FieldT::one() : FieldT::zero());
          for (counter = 0; counter < noIncomingPayments; counter++)
          {
            interm_incoming[counter][i] = interm_incoming[counter][i-1] * 2 + (r_incoming[counter][i] ? FieldT::one() : FieldT::zero());
          }
          for (counter = 0; counter < noOutgoingPayments; counter++)
          {
            interm_outgoing[counter][i] = interm_outgoing[counter][i-1] * 2 + (r_outgoing[counter][i] ? FieldT::one() : FieldT::zero());
          }
        }

        intermediate_startBalance.fill_with_field_elements(this->pb, interm_startBalance);
        intermediate_endBalance.fill_with_field_elements(this->pb, interm_endBalance);
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          intermediate_incoming[counter].fill_with_field_elements(this->pb, interm_incoming[counter]);
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          intermediate_outgoing[counter].fill_with_field_elements(this->pb, interm_outgoing[counter]);
        }

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r_startBalance->generate_r1cs_witness();
        h_r_endBalance->generate_r1cs_witness();
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          h_r_incoming[counter]->generate_r1cs_witness();
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          h_r_outgoing[counter]->generate_r1cs_witness();
        }
        unpack_inputs->generate_r1cs_witness_from_bits();

        h_startBalance_var->bits.fill_with_bits(this->pb, h_startBalance);
        h_endBalance_var->bits.fill_with_bits(this->pb, h_endBalance);
        for (counter = 0; counter < noIncomingPayments; counter++)
        {
          h_incoming_var[counter]->bits.fill_with_bits(this->pb, h_incoming[counter]);
        }
        for (counter = 0; counter < noOutgoingPayments; counter++)
        {
          h_outgoing_var[counter]->bits.fill_with_bits(this->pb, h_outgoing[counter]);
        }
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map_multi(const bit_vector &h_startBalance,
                                       const bit_vector &h_endBalance,
                                       const bit_vector *h_incoming,
                                       const bit_vector *h_outgoing
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.

    assert(h_startBalance.size() == sha256_digest_len);
    assert(h_endBalance.size() == sha256_digest_len);
    for (counter = 0; counter < noIncomingPayments; counter++)
    {
      assert(h_incoming[counter].size() == sha256_digest_len);
    }
    for (counter = 0; counter < noOutgoingPayments; counter++)
    {
      assert(h_outgoing[counter].size() == sha256_digest_len);
    }

    std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h_startBalance.begin(), h_startBalance.end());
    input_as_bits.insert(input_as_bits.end(), h_endBalance.begin(), h_endBalance.end());
    for (counter = 0; counter < noIncomingPayments; counter++)
    {
      input_as_bits.insert(input_as_bits.end(), h_incoming[counter].begin(), h_incoming[counter].end());
    }
    for (counter = 0; counter < noOutgoingPayments; counter++)
    {
      input_as_bits.insert(input_as_bits.end(), h_outgoing[counter].begin(), h_outgoing[counter].end());
    }
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);

    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;
}
