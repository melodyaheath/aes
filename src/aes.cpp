#include "aes.hpp"
#include <assert.h>
#include <cstddef>

#include <iostream>

namespace crypto {

using std::move;

void Aes::circular_byte_left_shift(vector<u8> &state, const size_t start, const size_t end) {
    assert(state.size() > end);
    assert(end > start);
 
    auto last_pointer = (state.begin() + end);
    auto first_value = *(state.begin() + start);

    for ( auto it = state.begin() + start + 1; 
        it != state.begin() + end + 1; 
        it++) {
        *(it - 1) = *it;
    }
    *last_pointer  = first_value;
}

void Aes::shift_rows(vector<u8> &state) {
    vector<u8> state_copy;

    // static constexpr array<size_t, 16> POSITIONS = {
    //      0,  4,  8, 12,
    //      5,  9, 13,  1,
    //     10, 14,  2,  6,
    //     15,  3,  7,  11      
    // };

    static constexpr array<size_t, 16> POSITIONS = {
         0,  5, 10, 15,
         4,  9, 14,  3,
         8, 13,  2,  7,
        12,  1,  6,  11      
    };

    for ( auto position : POSITIONS ) {
        state_copy.emplace_back(state.at(position));
    }
    
    state = move(state_copy);
}

void Aes::byte_substitution(vector<u8> &state, const size_t start, const size_t end) {
    assert(state.size() > end);
    assert(end > start);
    
    for  (auto it = state.begin() + start; it != state.begin() + end + 1; it++ ) {
        *it = SBOX[*it];
    }
}

void Aes::add_round_constant(u8& element, const size_t round) {
    static constexpr std::array<u8, 10> round_counts = {
        0x01, 0x02, 0x04, 0x08, 
        0x10, 0x20, 0x40, 0x80, 
        0x1B, 0x36
    };
    element ^= round_counts.at(round);
}
const vector<u8> Aes::operation_g(const vector<u8> &state, const size_t start, const size_t end, const size_t round) {
    assert(state.size() > end);
    assert(end > start);

    vector<u8> g_values = vector<u8>(state.cbegin() + start, state.cbegin() + end + 1);
    circular_byte_left_shift(g_values, 0, g_values.size() - 1);
    byte_substitution(g_values, 0, g_values.size() - 1);
    add_round_constant(g_values.at(0), round);
    
    return g_values;
}

const vector<u8> Aes::generate_next_roundkey(const size_t round, const vector<u8> &state) {
    auto counter = 0;
    auto next_round_key = vector<u8>(state.size(), 0);
    auto g_values = operation_g(state, 12, 15, round);

    for (auto byte = state.begin(); byte != state.end(); byte++) {
        if ( counter >= 0 && counter <= 3) {
            next_round_key[counter] = *byte ^ g_values[counter];
        }
        else {
            next_round_key[counter] = next_round_key[counter - 4] ^ *byte;
        }
        counter++;
    }

    return next_round_key;
}
void Aes::add_round_key_to_state(const vector<u8> &round_key, vector<u8>& state) {
    assert(state.size() == round_key.size());
    
    auto counter = 0;
    auto key_iterator = round_key.cbegin();
    auto state_iterator = state.begin();
    while ( counter != state.size() && state_iterator != state.end() && key_iterator != round_key.cend()) {
        (*state_iterator) ^= (*key_iterator);
        state_iterator++;
        key_iterator++;
        counter++;
    }
}

// COLUMNS ARE (0,1,2,3), (4,5,6,7), (8,9,10,11), (12,13,14,15)
// ROWS ARE   (0, 4, 8,  12), (1, 5, 9,  13), (2, 6, 10, 14), (3, 7, 11, 15)
// 00 3C 6E 47 
// 1F 4E 22 74 
// 0E 08 1B 31 
// 54 59 0B 1A

/*
    first row * first column is BA
    second row * first column 75
    first row * second column is 84

*/
/* 
    Taken from Wikipedia, I wish I understood this better. 
    https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
*/
u8 g256m(u8 a, u8 b) { 
    u8 p = 0;
    for (auto counter = 0; counter < 8; counter++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */ 
        }
        b >>= 1;
    }
    return p;
}

// 0x0 = row 0 * column 0
// 0x1 = row 1 * column 0
// 0x2 = row 2 * column 0
// 0x3 = row 3 * column 0
// 1x0 = row 0 * column 1
// 1x1 = row 1 * column 1
// 1x2 = row 2 * column 1
// 1x3 = row 3 * column 1




void Aes::mix_columns(vector<u8> &state) {
    static constexpr std::array<u8, 16> COLUMN_CONSTANTS = {
        2, 3, 1, 1,
        1, 2, 3, 1,
        1, 1, 2, 3,
        3, 1, 1, 2
    };

    vector<u8> next_state(state.size(), 0);


    for ( auto state_col = 0; state_col < 4; state_col++) {
        for (auto constants_row = 0; constants_row < 4; constants_row++) {
        
            // std::cout 
            //       << "next_state[" << constants_row << "+" << state_col*4 << "=" << constants_row+state_col*4 << "] = "
            //       << std::dec << (uint)COLUMN_CONSTANTS[constants_row*4+0] << " * "
            //       << std::hex << (uint)state[state_col*4+0]             << " ^ "
            //       << std::dec << (uint)COLUMN_CONSTANTS[constants_row*4+1] << " * "
            //       << std::hex << (uint)state[state_col*4+1]             << " ^ "
            //       << std::dec << (uint)COLUMN_CONSTANTS[constants_row*4+2] << " * "
            //       << std::hex << (uint)state[state_col*4+2]             << " ^ "
            //       << std::dec << (uint)COLUMN_CONSTANTS[constants_row*4+3] << " * "
            //       << std::hex << (uint)state[state_col*4+3];
            next_state[constants_row+state_col*4] = 
                g256m(COLUMN_CONSTANTS[constants_row*4+0], state[state_col*4+0] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+1], state[state_col*4+1] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+2], state[state_col*4+2] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+3], state[state_col*4+3] );

            // std::cout << " = " << std::hex << (uint)next_state[constants_row+state_col*4] << std::dec << "\n";
        }
    }



    state = move(next_state);
}


Aes::Aes(AesKeyWidth width) {
    assert(width == AesKeyWidth::AES_128 || width == AesKeyWidth::AES_256);
}

} /* namespace crypto */
