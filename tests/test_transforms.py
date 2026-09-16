from aes.sbox import INV_SBOX, SBOX
from aes.transforms import (
    add_round_key,
    bytes_to_state,
    inv_mix_columns,
    inv_shift_rows,
    mix_columns,
    shift_rows,
    state_to_bytes,
)


def test_sbox_known_values():
    assert SBOX[0x00] == 0x63
    assert SBOX[0x53] == 0xed
    assert SBOX[0xc2] == 0x25
    assert SBOX[0x9a] == 0xb8


def test_inv_sbox_undoes_sbox():
    assert all(INV_SBOX[SBOX[x]] == x for x in range(256))


def test_bytes_to_state_column_order():
    demo = bytes.fromhex("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34")
    state = bytes_to_state(demo)
    assert state[0] == 0x32 and state[1] == 0x43 and state[2] == 0xf6 and state[3] == 0xa8
    assert state[0 + 4 * 1] == 0x88


def test_state_to_bytes_round_trip():
    demo = bytes.fromhex("32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34")
    state = bytes_to_state(demo)
    assert state_to_bytes(state) == demo


def test_shift_rows_fips197_example():
    state = bytes_to_state(bytes.fromhex("d4 27 11 ae e0 bf 98 f1 b8 b4 5d e5 1e 41 52 30"))
    shift_rows(state)
    assert state_to_bytes(state) == bytes.fromhex("d4bf5d30e0b452aeb84111f11e2798e5")


def test_shift_rows_round_trip():
    state = bytes_to_state(bytes.fromhex("00112233445566778899aabbccddeeff"))
    original = bytes(state)
    shift_rows(state)
    inv_shift_rows(state)
    assert bytes(state) == original


def test_mix_columns_fips197_example():
    state = bytes_to_state(bytes.fromhex("d4 bf 5d 30 e0 b4 52 ae b8 41 11 f1 1e 27 98 e5"))
    mix_columns(state)
    assert state_to_bytes(state) == bytes.fromhex("046681e5e0cb199a48f8d37a2806264c")


def test_mix_columns_round_trip():
    state = bytes_to_state(bytes.fromhex("00112233445566778899aabbccddeeff"))
    original = bytes(state)
    mix_columns(state)
    inv_mix_columns(state)
    assert bytes(state) == original


def test_add_round_key_is_xor():
    original = bytes.fromhex("00112233445566778899aabbccddeeff")
    state = bytes_to_state(original)
    round_key = bytearray(range(16))
    add_round_key(state, round_key)
    assert state_to_bytes(state) == bytes(b ^ i for i, b in enumerate(original))
