#include "aes.hpp"
#include <assert.h>
#include <cstddef>

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
/* 
    Taken from Wikipedia, I wish I understood this better. 
    https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
    Refer to the C# example.
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
            next_state[constants_row+state_col*4] = 
                g256m(COLUMN_CONSTANTS[constants_row*4+0], state[state_col*4+0] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+1], state[state_col*4+1] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+2], state[state_col*4+2] ) ^
                g256m(COLUMN_CONSTANTS[constants_row*4+3], state[state_col*4+3] );
        }
    }



    state = move(next_state);
}

const vector<u8> Aes::encrypt(const vector<u8>& _key, const vector<u8>& _message) {
    assert(_key.size() == _message.size() && _key.size() == 16);

    vector<u8> message(_message.cbegin(), _message.cend());
    vector<u8> key(_key.cbegin(), _key.cend());

    add_round_key_to_state(key, message);


    for ( auto round = 0; round < 9; round++) {
        byte_substitution(message, 0, message.size() - 1);
        shift_rows(message);
        mix_columns(message);
        key = generate_next_roundkey(round, key);
        add_round_key_to_state(key, message);
    }

    byte_substitution(message, 0, message.size() - 1);
    shift_rows(message);

    const vector<u8> first_round_key = generate_next_roundkey(9, key);
    add_round_key_to_state(first_round_key, message);

    return message;
}

Aes::Aes(AesKeyWidth width) {
    assert(width == AesKeyWidth::AES_128 || width == AesKeyWidth::AES_256);
}

} /* namespace crypto */
