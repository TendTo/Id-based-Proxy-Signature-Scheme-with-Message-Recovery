#include "test-const.h"

char TEST_PAIRING_P[] = "type a\n\
q 7980668253729152545608928928653762711716145303455336350423036869116003844883908753281836182321024271040021357797014510798434797859229974438803725357408991\n\
h 10921189617418438496458770816510309189239573690725201985683358179020029217546508170827413694357792775987936\n\
r 730750818665451459101842416367364881864821047297\n\
exp2 159\n\
exp1 63\n\
sign1 1\n\
sign0 1\n\
hash_type 0\n\
P [3080255922072514454854761261637048229063060712234861160626067660516742899193538385939683974943106560975709068251613933839665767313796146065120889043558807, 7280559322651464525813104666108639481832422519363853361129767202449750369614988801604331314447051464218615115625151819688340160207751872108837244060305934]\n\
pk [1964065410410776451955588067209269048732978832987707301424669611382452469191330437646754675243233364986804570675322345071777791408921248525095238838354814, 3325695201202249912364364549331129480823406275444460731639151878105768305387402212383803570917220444339994034466993708073963493680228233434715710318719389]\n\
msk 117843337233255684997953208940058293206574021446\n";

const int sec_levels[N_SEC_LEVELS] = {80, 128};
const size_t sec_levels_order[N_SEC_LEVELS] = {80, 128};

const hash_type_t hash_types[N_HASH_TYPES] = {sha_1, sha_256, sha_512};
sv_identity_t TEST_IDENTITY = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
sv_identity_t TEST_IDENTITY_2 = {31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
const uint8_t TEST_IDENTITY_DIGEST_SHA1[SHA1_DIGEST_SIZE] = {174, 91, 216, 239, 234, 83, 34, 196, 217, 152, 109, 6, 104, 10, 120, 19, 146, 249, 166, 66};
const uint8_t TEST_IDENTITY_DIGEST_SHA256[SHA256_DIGEST_SIZE] = {99, 13, 205, 41, 102, 196, 51, 102, 145, 18, 84, 72, 187, 178, 91, 79, 244, 18, 164, 156, 115, 45, 178, 200, 171, 193, 184, 88, 27, 215, 16, 221};
const uint8_t TEST_IDENTITY_DIGEST_SHA512[SHA512_DIGEST_SIZE] = {61, 148, 238, 164, 156, 88, 10, 239, 129, 105, 53, 118, 43, 224, 73, 85, 157, 109, 20, 64, 222, 222, 18, 230, 161, 37, 241, 132, 31, 255, 142, 111, 169, 215, 24, 98, 163, 229, 116, 107, 87, 27, 227, 209, 135, 176, 4, 16, 70, 245, 46, 189, 133, 12, 124, 189, 95, 222, 142, 227, 132, 115, 182, 73};
const uint8_t TEST_ELEMENT_DIGEST_SHA1[SHA1_DIGEST_SIZE] = {154, 143, 18, 130, 101, 228, 140, 242, 203, 105, 27, 76, 239, 204, 192, 85, 109, 156, 189, 58};
const uint8_t TEST_ELEMENT_DIGEST_SHA256[SHA256_DIGEST_SIZE] = {233, 255, 14, 110, 109, 233, 93, 165, 111, 240, 159, 78, 62, 15, 72, 29, 103, 88, 95, 10, 104, 170, 253, 238, 240, 248, 111, 123, 133, 51, 206, 23};
const uint8_t TEST_ELEMENT_DIGEST_SHA512[SHA512_DIGEST_SIZE] = {160, 237, 224, 79, 173, 198, 48, 115, 203, 162, 233, 108, 204, 185, 88, 209, 57, 95, 235, 213, 162, 198, 108, 159, 223, 183, 240, 216, 57, 95, 143, 187, 22, 21, 174, 86, 181, 4, 43, 79, 244, 15, 33, 96, 113, 81, 197, 46, 83, 22, 27, 74, 124, 163, 63, 79, 150, 219, 153, 44, 86, 155, 29, 182};
const uint8_t TEST_MESSAGE_DIGEST_SHA1[SHA1_DIGEST_SIZE] = {175, 212, 248, 240, 11, 177, 23, 154, 49, 151, 4, 119, 186, 104, 21, 235, 128, 13, 148, 186};
const uint8_t TEST_MESSAGE_DIGEST_SHA256[] = {54, 83, 234, 33, 180, 230, 193, 229, 75, 176, 226, 155, 253, 242, 215, 15, 191, 144, 132, 212};
const hash_test_t hash_tests[N_HASH_TYPES] = {
    {sha_1, SHA1_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA1, TEST_ELEMENT_DIGEST_SHA1},
    {sha_256, SHA256_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA256, TEST_ELEMENT_DIGEST_SHA256},
    {sha_512, SHA512_DIGEST_SIZE, TEST_IDENTITY_DIGEST_SHA512, TEST_ELEMENT_DIGEST_SHA512}};
