#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"

const size_t sha256_digest_len = 256;

/*
computed by:

        unsigned long long bitlen = 256;

        unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
                                     bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
                                    };

        std::vector<bool> padding_bv(256);

        convertBytesToVector(padding, padding_bv);

        printVector(padding_bv);
*/
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

    pb_variable_array<FieldT> intermediate_val1;
    pb_variable_array<FieldT> intermediate_val2;
    pb_variable_array<FieldT> intermediate_val3;

    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */
    std::shared_ptr<digest_variable<FieldT>> h3_var; /* H(R2) */

    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */
    std::shared_ptr<digest_variable<FieldT>> r3_var; /* R3 */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2; /* hashing gadget for r2 */

    std::shared_ptr<block_variable<FieldT>> h_r3_block; /* 512 bit block that contains r3 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r3; /* hashing gadget for r3 */


    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    l_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 3;
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

        intermediate_val1.allocate(this->pb, sha256_digest_len/2, "intermediate_val1");
        intermediate_val2.allocate(this->pb, sha256_digest_len/2, "intermediate_val2");
        intermediate_val3.allocate(this->pb, sha256_digest_len/2, "intermediate_val3");


        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // Verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h1"));
        h2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h2"));
        h3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h3"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h3_var->bits.begin(), h3_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r1"));
        r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r2"));
        r3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r3"));

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



    }
    void generate_r1cs_constraints()
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();
        r3_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        // We are using half of the digest length as salt and the other half for the value
        unsigned int NN = sha256_digest_len/2; // 128

        // Step 2: We need to confirm that the (binary, big-endian encoded) values of 
        // r1_var->bits[0, ..., 127], r2_var->bits[0, ..., 127] and r3_var->bits[0, ..., 127] 
        // correspond to the decimal values in intermediate_val1, intermediate_val2 and 
        // intermediate_val3. Construct the vectors A, B and C such that they form an R1CS that checks  
        // the above.
        // 
        // A set of three vectors (A, B and C) will need to be constructed for each constraint. That is, 
        // atleast 3 sets of 3 vectors (i.e 9) will be required to complete this step. 
        // Note that there can be more.

        // <------------- TODO start -------------------->

        // This is an example of how a constraint is added to the protoboard.
        {
          auto A = 1;
          auto B = 1;
          auto C = 1;

          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  A,
                  B,
                  C),
              FMT(this->annotation_prefix, "", 0));
        }
        // <------------- TODO end -------------------->

        // <------------- TODO start -------------------->

        // Step 3: We need to confirm that r3 = r1 + r1. Add a constraint for this by constructing three 
        // vectors A, B and C. Refer to step 2 for more information on constraints.

        {
          auto A = 1;
          auto B = 1;
          auto C = 1;

          this->pb.add_r1cs_constraint(
              r1cs_constraint<FieldT>(
                  A,
                  B,
                  C),
              FMT(this->annotation_prefix, "", 0));
        }
        // <------------- TODO end -------------------->
        

        // These are the constraints to ensure the hashes validate.
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
        h_r3->generate_r1cs_constraints();
    }

    // The witness is simply the assignment to all the variables, including input, output and internal 
    // variables
    void generate_r1cs_witness(const bit_vector &h1,
                               const bit_vector &h2,
                               const bit_vector &h3,
                               const bit_vector &r1,
                               const bit_vector &r2,
                               const bit_vector &r3
                              )
    {
        // Fill our digests with our witnessed data
        r1_var->bits.fill_with_bits(this->pb, r1);
        r2_var->bits.fill_with_bits(this->pb, r2);
        r3_var->bits.fill_with_bits(this->pb, r3);
        
        size_t NN = sha256_digest_len/2; // 128
        
        // Step 1:

        // The values intermediate_val1, intermediate_val2 and intermediate_val3 need to be filled with
        // the decimal values of r1, r2 and r3, which are big-endian, binary encoded.
        //
        // The values stored in intermediate_val1, intermediate_val2 and intermediate_val3 as well as 
        // r1_var, r2_var and r3_var will be used to "run" against the constraints generated by the 
        // call to generate_r1cs_constraints()

        std::vector<FieldT> interm1(NN);
        std::vector<FieldT> interm2(NN);
        std::vector<FieldT> interm3(NN);

        // <------------- TODO start -------------------->


        // <------------- TODO end -------------------->

        intermediate_val1.fill_with_field_elements(this->pb, interm1);
        intermediate_val2.fill_with_field_elements(this->pb, interm2);
        intermediate_val3.fill_with_field_elements(this->pb, interm3);

        cout << "intermediate_val1[NN-1]: " << intermediate_val1.get_vals(this->pb)[NN-1] << endl;
        cout << "intermediate_val2[NN-1]: " << intermediate_val2.get_vals(this->pb)[NN-1] << endl;
        cout << "intermediate_val3[NN-1]: " << intermediate_val3.get_vals(this->pb)[NN-1] << endl;
        
        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        h_r3->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->pb, h1);
        h2_var->bits.fill_with_bits(this->pb, h2);
        h3_var->bits.fill_with_bits(this->pb, h3);
    }
};

template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1,
                                             const bit_vector &h2,
                                             const bit_vector &h3
                                            )
{
    // Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    assert(h1.size() == sha256_digest_len);
    assert(h2.size() == sha256_digest_len);
    assert(h3.size() == sha256_digest_len);

    std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());
    input_as_bits.insert(input_as_bits.end(), h2.begin(), h2.end());
    input_as_bits.insert(input_as_bits.end(), h3.begin(), h3.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);

    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;
}
