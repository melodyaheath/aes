#include <iostream>
#include <sstream>
#include <assert.h>
#include "aes.hpp"
using namespace std;
using namespace crypto;

auto aes = new Aes(AesKeyWidth::AES_128);

void test_circular_shift() {
    u32 tested = aes->circular_byte_left_shift(0x67204675);
    u32 expected = 0x20467567;
    cout << "["<< __FUNCTION__ <<"] "
        << "Tested: 0x" << std::hex << tested << " | Expected: 0x" << std::hex << expected << "\n";
    assert(tested == expected);
}

void test_byte_substitution() {
    u32 tested = aes->byte_substitution(0x20467567);
    u32 expected = 0xB75A9D85;
    cout << "["<< __FUNCTION__ <<"] "
        << "Tested: 0x" << std::hex <<  tested << " | Expected: 0x" << std::hex << expected << "\n";
    assert(tested == expected);
}

void test_add_round_constant() {
    u32 tested = aes->add_round_constant(0, 0xB75A9D85);
    u32 expected = 0xB65A9D85;
    cout << "["<< __FUNCTION__ <<"] "
        << "Tested: 0x" << std::hex <<  tested << " | Expected: 0x" << std::hex << expected << "\n";
    assert(tested == expected);
}

void test_operation_g() {
    u32 tested = aes->operation_g(0, 0x67204675);
    u32 expected = 0xB65A9D85;
    cout << "["<< __FUNCTION__ <<"] "
        << "Tested: 0x" << std::hex <<  tested << " | Expected: 0x" << std::hex << expected << "\n";
    assert(tested == expected);
}

void test_generate_next_state() {
    std::array<u32, 4> start_state = { 0x54686174, 0x73206D79, 0x204B756E, 0x67204675 };
    std::array<u32, 4> tested = aes->generate_next_state(0, start_state);
    std::array<u32, 4> expected = {0xE232FCF1, 0x91129188, 0xB159E4E6, 0xD679A293};

    cout << "["<< __FUNCTION__ <<"] " << "Tested: ";
    for (auto it = tested.cbegin(); it != tested.cend(); it++) {
        cout << "0x" << std::hex <<  (*it) << " ";
    }
    cout << "\n";
    cout << "["<< __FUNCTION__ <<"] " << "Expected: ";
    for (auto it = expected.cbegin(); it != expected.cend(); it++) {
        cout << "0x" << std::hex <<  (*it) << " ";
    }
    cout <<"\n";

    assert(tested == expected);
} 



void test_apply_round_to_state() {
    std::array<u32, 4> tested_state = {0x54776F20, 0x4F6E6520, 0x4E696E65, 0x2054776F};
    std::array<u32, 4> tested_round_key = {0x54686174, 0x73206D79, 0x204B756E, 0x67204675};
    
    std::array<u32, 4> tested = aes->add_round_key_to_state(tested_round_key, tested_state);
    std::array<u32, 4> expected = {0x001f0e54, 0x3c4e0859, 0x6e221b0b, 0x4774311a};

    cout << "["<< __FUNCTION__ <<"] " << "Tested: ";
    for (auto it = tested.cbegin(); it != tested.cend(); it++) {
        cout << "0x" << std::hex <<  (*it) << " ";
    }
    cout << "\n";
    cout << "["<< __FUNCTION__ <<"] " << "Expected: ";
    for (auto it = expected.cbegin(); it != expected.cend(); it++) {
        cout << "0x" << std::hex <<  (*it) << " ";
    }
    cout <<"\n";

    assert(tested == expected);
} 

int main(int argc, char** argv) {
    test_circular_shift();
    test_byte_substitution();
    test_add_round_constant();
    test_operation_g();
    test_generate_next_state();
    test_apply_round_to_state();

}