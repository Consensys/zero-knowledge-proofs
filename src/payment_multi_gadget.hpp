#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libff/algebra/fields/field_utils.hpp"

using namespace libff;

const size_t sha256_digest_len = 256;

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

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

    pb_variable_array<FieldT> intermediate_startBalance;
    pb_variable_array<FieldT> intermediate_endBalance;
    pb_variable_array<FieldT> intermediate_incoming1;
    pb_variable_array<FieldT> intermediate_incoming2;
    pb_variable_array<FieldT> intermediate_outgoing1;
    pb_variable_array<FieldT> intermediate_outgoing2;

    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h_startBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> h_endBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> h_incoming1_var; 
    std::shared_ptr<digest_variable<FieldT>> h_incoming2_var; 
    std::shared_ptr<digest_variable<FieldT>> h_outgoing1_var; 
    std::shared_ptr<digest_variable<FieldT>> h_outgoing2_var; 

    std::shared_ptr<digest_variable<FieldT>> r_startBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> r_endBalance_var; 
    std::shared_ptr<digest_variable<FieldT>> r_incoming1_var; 
    std::shared_ptr<digest_variable<FieldT>> r_incoming2_var; 
    std::shared_ptr<digest_variable<FieldT>> r_outgoing1_var; 
    std::shared_ptr<digest_variable<FieldT>> r_outgoing2_var; 

    std::shared_ptr<block_variable<FieldT>> h_r_startBalance_block; /* 512 bit block that contains startBalance + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_startBalance; /* hashing gadget for startBalance */

    std::shared_ptr<block_variable<FieldT>> h_r_endBalance_block; /* 512 bit block that contains endBalance + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_endBalance; /* hashing gadget for endBalance */

    std::shared_ptr<block_variable<FieldT>> h_r_incoming1_block; /* 512 bit block that contains incoming1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_incoming1; /* hashing gadget for incoming1 */

    std::shared_ptr<block_variable<FieldT>> h_r_incoming2_block; /* 512 bit block that contains incoming2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_incoming2; /* hashing gadget for incoming2 */

    std::shared_ptr<block_variable<FieldT>> h_r_outgoing1_block; /* 512 bit block that contains outgoing1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_outgoing1; /* hashing gadget for outgoing1 */

    std::shared_ptr<block_variable<FieldT>> h_r_outgoing2_block; /* 512 bit block that contains outgoing2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r_outgoing2; /* hashing gadget for outgoing2 */

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    payment_multi_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "payment_multi_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 6;
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
        intermediate_incoming1.allocate(this->pb, sha256_digest_len/2, "intermediate_incoming1");
        intermediate_incoming2.allocate(this->pb, sha256_digest_len/2, "intermediate_incoming2");
        intermediate_outgoing1.allocate(this->pb, sha256_digest_len/2, "intermediate_outgoing1");
        intermediate_outgoing2.allocate(this->pb, sha256_digest_len/2, "intermediate_outgoing2");

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
        h_incoming1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_incoming1"));
        h_incoming2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_incoming2"));
        h_outgoing1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_outgoing1"));
        h_outgoing2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h_outgoing2"));

        input_as_bits.insert(input_as_bits.end(), h_startBalance_var->bits.begin(), h_startBalance_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_endBalance_var->bits.begin(), h_endBalance_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_incoming1_var->bits.begin(), h_incoming1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_incoming2_var->bits.begin(), h_incoming2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_outgoing1_var->bits.begin(), h_outgoing1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h_outgoing2_var->bits.begin(), h_outgoing2_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r_startBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_startBalance"));
        r_endBalance_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_endBalance"));
        r_incoming1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_incoming1"));
        r_incoming2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_incoming2"));
        r_outgoing1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_outgoing1"));
        r_outgoing2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r_outgoing2"));

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

        h_r_incoming1_block.reset(new block_variable<FieldT>(pb, {
            r_incoming1_var->bits,
            padding_var
        }, "h_r_incoming1_block"));

        h_r_incoming1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_incoming1_block->bits,
                                                                  *h_incoming1_var,
                                                                  "h_r_incoming1"));

        h_r_incoming2_block.reset(new block_variable<FieldT>(pb, {
            r_incoming2_var->bits,
            padding_var
        }, "h_r_incoming2_block"));

        h_r_incoming2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_incoming2_block->bits,
                                                                  *h_incoming2_var,
                                                                  "h_r_incoming2"));

        h_r_outgoing1_block.reset(new block_variable<FieldT>(pb, {
            r_outgoing1_var->bits,
            padding_var
        }, "h_r_outgoing1_block"));

        h_r_outgoing1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_outgoing1_block->bits,
                                                                  *h_outgoing1_var,
                                                                  "h_r_outgoing1"));

        h_r_outgoing2_block.reset(new block_variable<FieldT>(pb, {
            r_outgoing2_var->bits,
            padding_var
        }, "h_r_outgoing2_block"));

        h_r_outgoing2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r_outgoing2_block->bits,
                                                                  *h_outgoing2_var,
                                                                  "h_r_outgoing2"));

    }
    void generate_payment_multi_constraints()
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r_startBalance_var->generate_r1cs_constraints();
        r_endBalance_var->generate_r1cs_constraints();
        r_incoming1_var->generate_r1cs_constraints();
        r_incoming2_var->generate_r1cs_constraints();
        r_outgoing1_var->generate_r1cs_constraints();
        r_outgoing2_var->generate_r1cs_constraints();

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

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_incoming1[0],
                    1, 
                    r_incoming1_var->bits[0]),
                FMT(this->annotation_prefix, " zero3_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_incoming2[0],
                    1, 
                    r_incoming2_var->bits[0]),
                FMT(this->annotation_prefix, " zero4_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_outgoing1[0],
                    1, 
                    r_outgoing1_var->bits[0]),
                FMT(this->annotation_prefix, " zero5_%zu", 0));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intermediate_outgoing2[0],
                    1, 
                    r_outgoing2_var->bits[0]),
                FMT(this->annotation_prefix, " zero6_%zu", 0));

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

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_incoming1[i] },
                    { 1 }, 
                    { intermediate_incoming1[i-1] * 2, r_incoming1_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum3_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_incoming2[i] },
                    { 1 }, 
                    { intermediate_incoming2[i-1] * 2, r_incoming2_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum4_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_outgoing1[i] },
                    { 1 }, 
                    { intermediate_outgoing1[i-1] * 2, r_outgoing1_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum5_%zu", i));

            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_outgoing2[i] },
                    { 1 }, 
                    { intermediate_outgoing2[i-1] * 2, r_outgoing2_var->bits[i] }), 
                FMT(this->annotation_prefix, " sum6_%zu", i));

        }


        // Constraint that start bal + incoming = end bal + outgoing

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                { intermediate_startBalance[NN-1], intermediate_incoming1[NN-1], intermediate_incoming2[NN-1]},
                { 1 },
                { intermediate_endBalance[NN-1], intermediate_outgoing1[NN-1], intermediate_outgoing2[NN-1]}), 
            FMT(this->annotation_prefix, "finalsum_%zu", 0));
        

        // These are the constraints to ensure the hashes validate.
        h_r_startBalance->generate_r1cs_constraints();
        h_r_endBalance->generate_r1cs_constraints();
        h_r_incoming1->generate_r1cs_constraints();
        h_r_incoming2->generate_r1cs_constraints();
        h_r_outgoing1->generate_r1cs_constraints();
        h_r_outgoing2->generate_r1cs_constraints();
    }

    void generate_payment_multi_witness(const bit_vector &h_startBalance,
                               const bit_vector &h_endBalance,
                               const bit_vector &h_incoming1,
                               const bit_vector &h_incoming2,
                               const bit_vector &h_outgoing1,
                               const bit_vector &h_outgoing2,
                               const bit_vector &r_startBalance,
                               const bit_vector &r_endBalance,
                               const bit_vector &r_incoming1,
                               const bit_vector &r_incoming2,
                               const bit_vector &r_outgoing1,
                               const bit_vector &r_outgoing2
                              )
    {
        // Fill our digests with our witnessed data
        r_startBalance_var->bits.fill_with_bits(this->pb, r_startBalance);
        r_endBalance_var->bits.fill_with_bits(this->pb, r_endBalance);
        r_incoming1_var->bits.fill_with_bits(this->pb, r_incoming1);
        r_incoming2_var->bits.fill_with_bits(this->pb, r_incoming2);
        r_outgoing1_var->bits.fill_with_bits(this->pb, r_outgoing1);
        r_outgoing2_var->bits.fill_with_bits(this->pb, r_outgoing2);
        
        size_t NN = sha256_digest_len/2;
        
        std::vector<FieldT> interm_startBalance(NN);
        std::vector<FieldT> interm_endBalance(NN);
        std::vector<FieldT> interm_incoming1(NN);
        std::vector<FieldT> interm_incoming2(NN);
        std::vector<FieldT> interm_outgoing1(NN);
        std::vector<FieldT> interm_outgoing2(NN);

        interm_startBalance[0] = r_startBalance[0] ? FieldT::one() : FieldT::zero();
        interm_endBalance[0] = r_endBalance[0] ? FieldT::one() : FieldT::zero();
        interm_incoming1[0] = r_incoming1[0] ? FieldT::one() : FieldT::zero();
        interm_incoming2[0] = r_incoming2[0] ? FieldT::one() : FieldT::zero();
        interm_outgoing1[0] = r_outgoing1[0] ? FieldT::one() : FieldT::zero();
        interm_outgoing2[0] = r_outgoing2[0] ? FieldT::one() : FieldT::zero();

        for (size_t i=1; i<NN; i++) {
          interm_startBalance[i] = interm_startBalance[i-1] * 2 + (r_startBalance[i] ? FieldT::one() : FieldT::zero());
          interm_endBalance[i] = interm_endBalance[i-1] * 2 + (r_endBalance[i] ? FieldT::one() : FieldT::zero());
          interm_incoming1[i] = interm_incoming1[i-1] * 2 + (r_incoming1[i] ? FieldT::one() : FieldT::zero());
          interm_incoming2[i] = interm_incoming2[i-1] * 2 + (r_incoming2[i] ? FieldT::one() : FieldT::zero());
          interm_outgoing1[i] = interm_outgoing1[i-1] * 2 + (r_outgoing1[i] ? FieldT::one() : FieldT::zero());
          interm_outgoing2[i] = interm_outgoing2[i-1] * 2 + (r_outgoing2[i] ? FieldT::one() : FieldT::zero());
        }

        intermediate_startBalance.fill_with_field_elements(this->pb, interm_startBalance);
        intermediate_endBalance.fill_with_field_elements(this->pb, interm_endBalance);
        intermediate_incoming1.fill_with_field_elements(this->pb, interm_incoming1);
        intermediate_incoming2.fill_with_field_elements(this->pb, interm_incoming2);
        intermediate_outgoing1.fill_with_field_elements(this->pb, interm_outgoing1);
        intermediate_outgoing2.fill_with_field_elements(this->pb, interm_outgoing2);

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r_startBalance->generate_r1cs_witness();
        h_r_endBalance->generate_r1cs_witness();
        h_r_incoming1->generate_r1cs_witness();
        h_r_incoming2->generate_r1cs_witness();
        h_r_outgoing1->generate_r1cs_witness();
        h_r_outgoing2->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h_startBalance_var->bits.fill_with_bits(this->pb, h_startBalance);
        h_endBalance_var->bits.fill_with_bits(this->pb, h_endBalance);
        h_incoming1_var->bits.fill_with_bits(this->pb, h_incoming1);
        h_incoming2_var->bits.fill_with_bits(this->pb, h_incoming2);
        h_outgoing1_var->bits.fill_with_bits(this->pb, h_outgoing1);
        h_outgoing2_var->bits.fill_with_bits(this->pb, h_outgoing2);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map_multi(const bit_vector &h_startBalance,
                                       const bit_vector &h_endBalance,
                                       const bit_vector &h_incoming1,
                                       const bit_vector &h_incoming2,
                                       const bit_vector &h_outgoing1,
                                       const bit_vector &h_outgoing2
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.

    assert(h_startBalance.size() == sha256_digest_len);
    assert(h_endBalance.size() == sha256_digest_len);
    assert(h_incoming1.size() == sha256_digest_len);
    assert(h_incoming2.size() == sha256_digest_len);
    assert(h_outgoing1.size() == sha256_digest_len);
    assert(h_outgoing2.size() == sha256_digest_len);

    std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h_startBalance.begin(), h_startBalance.end());
    input_as_bits.insert(input_as_bits.end(), h_endBalance.begin(), h_endBalance.end());
    input_as_bits.insert(input_as_bits.end(), h_incoming1.begin(), h_incoming1.end());
    input_as_bits.insert(input_as_bits.end(), h_incoming2.begin(), h_incoming2.end());
    input_as_bits.insert(input_as_bits.end(), h_outgoing1.begin(), h_outgoing1.end());
    input_as_bits.insert(input_as_bits.end(), h_outgoing2.begin(), h_outgoing2.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);

    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;
}
