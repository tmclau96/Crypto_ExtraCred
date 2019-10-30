# decrypting des

#following with no s boxes
def decryption(message, key):
    assert isinstance(message, int) and isinstance(key,int)  # may need to change for broken des
    assert not message.bit_length() > 64
    assert not key.bit_length() > 64

    # permutation  key
    key = permutation_by_table(key, 64, key_permutation)

    # split and generate 16 round keys
    C0 = key >>28
    D0 = key & (2**28-1)
    round_keys = generate_keys(C0,D0)
    message_block = permutation_by_table(message, 64, initial_permutation)
    L0 = message_block >> 32
    R0 = message_block & (2**32-1)

    L_last = L0
    R_last = R0

    for i in range(1,17):
# In the encryption the code is the reversed order for decryption
            i=17-i
R_last = R_round
L_last = L_round
R_round = L_last ^ round_function(R_last, round_keys[i])
L_round = R_Last
L_round = R_last



cipher_block = (R_round << 32) + L_round

    # final permutation
cipher_block = permutation_by_table(cipher_block, 64, final_permutation)

#return cipher_block


def permutation_by_table(block, block_length, table):
    block_str = bin(block)[2:].zfill(block_length)
    perm = []
    for pos in range(len(table)):
        perm.append(block_str[table[pos] - 1])
    return int(''.join(perm), 2)

def generate_keys(C0,D0):

    round_keys = dict.fromkeys(range(0,17))

    #left rotation function
    lrot = lambda val, r_bits, max_bits: \
        (val << r_bits%max_bits) & (2**max_bits-1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

    # initial rotation
    C0 = lrot(C0, 0, 28)
    D0 = lrot(D0, 0, 28)
    round_keys[0] = (C0, D0)

    # create 16 more keys
    for i, rot_val in enumerate(shift):
        i += 1
        Ci = lrot(round_keys[i - 1][0], rot_val, 28)
        Di = lrot(round_keys[i - 1][1], rot_val, 28)
        round_keys[i] = (Ci, Di)

    del round_keys[0]

    for i, (Ci, Di) in round_keys.items():
        Ki = (Ci << 28) + Di
        round_keys[i] = permutation_by_table(Ki, 56, ki_permutation)

    return round_keys

def round_function(Ri, Ki):
    # expanding function for permutation
    Ri = permutation_by_table(Ri, 32, expansion_permutation)

    # XOR with key
    Ri ^= Ki

    # split ri
    Ri_blocks = [((Ri & (0b111111 << shift_val)) >> shift_val) for shift_val in (42, 36, 30, 24, 18, 12, 6, 0)]

    # look up in sbox
    for i, block in enumerate(Ri_blocks):
        row = ((0b100000 & block) >> 4) + (0b1 & block)
        col = (0b011110 & block) >> 1
        Ri_blocks[i] = s_boxes[i][16 * row + col]

    Ri_blocks = zip(Ri_blocks, (28, 24, 20, 16, 12, 8, 4, 0))
    Ri = 0
    for block, lshift_val in Ri_blocks:
        Ri += (block << lshift_val)

    Ri = permutation_by_table(Ri, 32, every_round_permutation)

    return Ri


def main():
    message = 0x8787878787878787
    key = 0x0e329232ea6d0d73

    print(' The key:       {:x}'.format(key))
    print('Given message:   {:x}'.format(message))
    cipher_text = decryption(message, key)
    print('decrypted: {:x}'.format(cipher_text))
