from aes.key_schedule import key_expansion


def test_key_expansion_fips197_appendix_a():
    round_keys, nr = key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert nr == 10
    assert len(round_keys) == 11
    assert bytes(round_keys[0]) == bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert bytes(round_keys[1]) == bytes.fromhex("a0fafe1788542cb123a339392a6c7605")
    assert bytes(round_keys[10]) == bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")


def test_number_of_rounds_per_key_size():
    assert key_expansion(b"\x00" * 16)[1] == 10
    assert key_expansion(b"\x00" * 24)[1] == 12
    assert key_expansion(b"\x00" * 32)[1] == 14
