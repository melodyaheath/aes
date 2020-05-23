#include "aes.hpp"
#include <assert.h>
#include <cstddef>

namespace crypto {

u32 Aes::circular_byte_left_shift(size_t row) {
    state->at(row*4) += 1;
    return ( data << 8 ) | ( data >> 24);
}
u32 Aes::byte_substitution(u32 data) {
    const size_t a = static_cast<size_t>((data & 0xFF));
    const size_t b = static_cast<size_t>((data & 0xFF00) >> 8);
    const size_t c = static_cast<size_t>((data & 0xFF0000) >> 16);
    const size_t d = static_cast<size_t>((data & 0xFF000000) >> 24);
    
    return static_cast<u32>(SBOX[a]) +
        static_cast<u32>(SBOX[b] << 8) +
        static_cast<u32>(SBOX[c] << 16) +
        static_cast<u32>(SBOX[d] << 24);
}
u32 Aes::add_round_constant(size_t round, u32 data) {
    static constexpr std::array<u32, 10> round_counts = {
        static_cast<u32>(0x01) << 24, static_cast<u32>(0x02) << 24, static_cast<u32>(0x04) << 24, static_cast<u32>(0x08) << 24, 
        static_cast<u32>(0x10) << 24, static_cast<u32>(0x20) << 24, static_cast<u32>(0x40) << 24, static_cast<u32>(0x80) << 24, 
        static_cast<u32>(0x1B) << 24, static_cast<u32>(0x36) << 24
    };
    return data ^ round_counts.at(round);
}
u32 Aes::operation_g(size_t round, u32 input) {
    input = circular_byte_left_shift(input);
    input = byte_substitution(input);
    input = add_round_constant(round, input);
    return input;
}
std::array<u32, 4> Aes::generate_next_state(size_t round, std::array<u32, 4> state) {

    const u32 state_a = state[0] ^ operation_g(0, state[3]);
    const u32 state_b = state_a ^ state[1];
    const u32 state_c = state_b ^ state[2];
    const u32 state_d = state_c ^ state[3];

    return {state_a, state_b, state_c, state_d};
}

std::array<u8, 4> Aes::mix_column(std::array<u8, 4> row) {
    static constexpr std::array<u8, 16> COLUMN_CONSTANTS = {
        2, 1, 1, 1,
        3, 2, 1, 1,
        1, 3, 2, 1,
        1, 1, 3, 2
    };

    const u8 row_a = 
        (row[0] * COLUMN_CONSTANTS[0]) ^
        (row[1] * COLUMN_CONSTANTS[1]) ^
        (row[2] * COLUMN_CONSTANTS[2]) ^
        (row[3] * COLUMN_CONSTANTS[3]);

    const u8 row_b = 
        (row[0] * COLUMN_CONSTANTS[4]) ^
        (row[1] * COLUMN_CONSTANTS[5]) ^
        (row[2] * COLUMN_CONSTANTS[6]) ^
        (row[3] * COLUMN_CONSTANTS[7]);
    
    const u8 row_c = 
        (row[0] * COLUMN_CONSTANTS[8]) ^
        (row[1] * COLUMN_CONSTANTS[9]) ^
        (row[2] * COLUMN_CONSTANTS[10]) ^
        (row[3] * COLUMN_CONSTANTS[11]);
    
    const u8 row_d = 
        (row[0] * COLUMN_CONSTANTS[12]) ^
        (row[1] * COLUMN_CONSTANTS[13]) ^
        (row[2] * COLUMN_CONSTANTS[14]) ^
        (row[3] * COLUMN_CONSTANTS[15]);

    return {row_a, row_b, row_c, row_d};

}


std::array<u32, 4> Aes::mix_all_columns(std::array<u32, 4> state) {

    u8* byte_state = reinterpret_cast<u8*>(state.data());

    std::array<u8, 4> row_a = mix_column( { byte_state[0], byte_state[5], byte_state[ 9], byte_state[13]});
    std::array<u8, 4> row_b = mix_column( { byte_state[1], byte_state[6], byte_state[10], byte_state[14]});
    std::array<u8, 4> row_c = mix_column( { byte_state[2], byte_state[7], byte_state[11], byte_state[15]});
    std::array<u8, 4> row_d = mix_column( { byte_state[3], byte_state[8], byte_state[12], byte_state[16]});
    
    

    return {


    };
}

std::array<u32, 4> Aes::add_round_key_to_state(std::array<u32, 4> state, std::array<u32, 4> round_key) {
    const u32 state_a = state[0] ^ round_key[0];
    const u32 state_b = state[1] ^ round_key[1];
    const u32 state_c = state[2] ^ round_key[2];
    const u32 state_d = state[3] ^ round_key[3];

    return {state_a, state_b, state_c, state_d};
}
Aes::Aes(AesKeyWidth width) {
    assert(width == AesKeyWidth::AES_128 || width == AesKeyWidth::AES_256);
}

} /* namespace crypto */
