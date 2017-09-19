#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libff/algebra/fields/field_utils.hpp"

using namespace libff;

const size_t sha256_digest_len1 = 256;

bool sha256_padding1[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT>
class payment_in_out_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

    pb_variable_array<FieldT> intermediate_startBalance;
    pb_variable_array<FieldT> intermediate_endBalance;
    pb_variable_array<FieldT> intermediate_incoming;
    pb_variable_array<FieldT> intermediate_outgoing;

    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */
    std::shared_ptr<digest_variable<FieldT>> h3_var; /* H(R3) */
    std::shared_ptr<digest_variable<FieldT>> h4_var; /* H(R4) */

    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */
    std::shared_ptr<digest_variable<FieldT>> r3_var; /* R3 */
    std::shared_ptr<digest_variable<FieldT>> r4_var; /* R4 */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2; /* hashing gadget for r2 */

    std::shared_ptr<block_variable<FieldT>> h_r3_block; /* 512 bit block that contains r3 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r3; /* hashing gadget for r3 */

    std::shared_ptr<block_variable<FieldT>> h_r4_block; /* 512 bit block that contains r4 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r4; /* hashing gadget for r4 */

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    payment_in_out_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "payment_in_out_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len1 * 4;
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

        intermediate_startBalance.allocate(this->pb, sha256_digest_len1/2, "intermediate_startBalance");
        intermediate_endBalance.allocate(this->pb, sha256_digest_len1/2, "intermediate_endBalance");
        intermediate_incoming.allocate(this->pb, sha256_digest_len1/2, "intermediate_incoming");
        intermediate_outgoing.allocate(this->pb, sha256_digest_len1/2, "intermediate_outgoing");

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding1[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // Verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "h1"));
        h2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "h2"));
        h3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "h3"));
        h4_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "h4"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h3_var->bits.begin(), h3_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h4_var->bits.begin(), h4_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "r1"));
        r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "r2"));
        r3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "r3"));
        r4_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len1, "r4"));

        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // Initialize the block gadget for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(pb, {
            r1_var->bits,
            padding_var
        }, "h_r1_block"));

        // Initialize the hash gadget for r1's hash
        h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r1_block->bits,
                                                                  *h1_var,
                                                                  "h_r1"));

        // Initialize the block gadget for r2's hash
        h_r2_block.reset(new block_variable<FieldT>(pb, {
            r2_var->bits,
            padding_var
        }, "h_r2_block"));

        // Initialize the hash gadget for r2's hash
        h_r2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r2_block->bits,
                                                                  *h2_var,
                                                                  "h_r2"));

        // Initialize the block gadget for r3's hash
        h_r3_block.reset(new block_variable<FieldT>(pb, {
            r3_var->bits,
            padding_var
        }, "h_r3_block"));

        // Initialize the hash gadget for r3's hash
        h_r3.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r3_block->bits,
                                                                  *h3_var,
                                                                  "h_r3"));

        // Initialize the block gadget for r4's hash
        h_r4_block.reset(new block_variable<FieldT>(pb, {
            r4_var->bits,
            padding_var
        }, "h_r4_block"));

        // Initialize the hash gadget for r4's hash
        h_r4.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r4_block->bits,
                                                                  *h4_var,
                                                                  "h_r4"));
    }
    void generate_payment_in_out_constraints()
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();
        r3_var->generate_r1cs_constraints();
        r4_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        unsigned int NN = sha256_digest_len1/2;
        // a = intermediate_val
        // Constraint a[0] = r[0]
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_startBalance[0],
                    1, 
                    r1_var->bits[0]),
                FMT(this->annotation_prefix, " zero1_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_endBalance[0],
                    1, 
                    r2_var->bits[0]),
                FMT(this->annotation_prefix, " zero2_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_incoming[0],
                    1, 
                    r3_var->bits[0]),
                FMT(this->annotation_prefix, " zero3_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_outgoing[0],
                    1, 
                    r4_var->bits[0]),
                FMT(this->annotation_prefix, " zero4_%zu", 0));

        for (unsigned int i = 1; i < NN; i++) {
          // a[i] = 2*a[i-1] + r[i]
          //
          // Constraint containing the intermediate steps in the calculation
          // a[NN-1] = \sum_{i=0}^{NN-1} 2^i * r[NN-1-i]
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_startBalance[i] },
                    { ONE },
                  { intermediate_startBalance[i-1] * 2 , r1_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum1_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_endBalance[i] },
                    { 1 }, 
                    { intermediate_endBalance[i-1] * 2, r2_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum2_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_incoming[i] },
                    { 1 }, 
                    { intermediate_incoming[i-1] * 2, r3_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum3_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_outgoing[i] },
                    { 1 }, 
                    { intermediate_outgoing[i-1] * 2, r4_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum4_%zu", i));
        }


        // Constraint that start bal + incoming = end bal + outgoing
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_startBalance[NN-1], intermediate_incoming[NN-1]},
                    { 1 },
                    { intermediate_endBalance[NN-1], intermediate_outgoing[NN-1]}), 
                FMT(this->annotation_prefix, "finalsum_%zu", 0));
      

        // These are the constraints to ensure the hashes validate.
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
        h_r3->generate_r1cs_constraints();
        h_r4->generate_r1cs_constraints();
    }

    void generate_payment_in_out_witness(const bit_vector &h_startBalance,
                               const bit_vector &h_endBalance,
                               const bit_vector &h_incoming,
                               const bit_vector &h_outgoing,
                               const bit_vector &r_startBalance,
                               const bit_vector &r_endBalance,
                               const bit_vector &r_incoming,
                               const bit_vector &r_outgoing
                              )
    {
        // Fill our digests with our witnessed data
        r1_var->bits.fill_with_bits(this->pb, r_startBalance);
        r2_var->bits.fill_with_bits(this->pb, r_endBalance);
        r3_var->bits.fill_with_bits(this->pb, r_incoming);
        r4_var->bits.fill_with_bits(this->pb, r_outgoing);
        
        size_t NN = sha256_digest_len1/2;
        
        std::vector<FieldT> interm1(NN);
        std::vector<FieldT> interm2(NN);
        std::vector<FieldT> interm3(NN);
        std::vector<FieldT> interm4(NN);

        interm1[0] = r_startBalance[0] ? FieldT::one() : FieldT::zero();
        interm2[0] = r_endBalance[0] ? FieldT::one() : FieldT::zero();
        interm3[0] = r_incoming[0] ? FieldT::one() : FieldT::zero();
        interm4[0] = r_outgoing[0] ? FieldT::one() : FieldT::zero();

        for (size_t i=1; i<NN; i++) {
          interm1[i] = interm1[i-1] * 2 + (r_startBalance[i] ? FieldT::one() : FieldT::zero());
          interm2[i] = interm2[i-1] * 2 + (r_endBalance[i] ? FieldT::one() : FieldT::zero());
          interm3[i] = interm3[i-1] * 2 + (r_incoming[i] ? FieldT::one() : FieldT::zero());
          interm4[i] = interm4[i-1] * 2 + (r_outgoing[i] ? FieldT::one() : FieldT::zero());
        }

        intermediate_startBalance.fill_with_field_elements(this->pb, interm1);
        intermediate_endBalance.fill_with_field_elements(this->pb, interm2);
        intermediate_incoming.fill_with_field_elements(this->pb, interm3);
        intermediate_outgoing.fill_with_field_elements(this->pb, interm4);

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        h_r3->generate_r1cs_witness();
        h_r4->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->pb, h_startBalance);
        h2_var->bits.fill_with_bits(this->pb, h_endBalance);
        h3_var->bits.fill_with_bits(this->pb, h_incoming);
        h4_var->bits.fill_with_bits(this->pb, h_outgoing);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                       const bit_vector &h2,
                                       const bit_vector &h3,
                                       const bit_vector &h4
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.

    assert(h1.size() == sha256_digest_len1);
    assert(h2.size() == sha256_digest_len1);
    assert(h3.size() == sha256_digest_len1);
    assert(h4.size() == sha256_digest_len1);

    std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    input_as_bits.insert(input_as_bits.end(), h3.begin(), h3.end());
    input_as_bits.insert(input_as_bits.end(), h4.begin(), h4.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);

    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;
}
