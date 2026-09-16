from aes.gf import mul, xtime


def test_xtime_without_reduction():
    assert xtime(0x1d) == 0x3a


def test_xtime_with_reduction():
    assert xtime(0x87) == 0x15


def test_mul_known_vector():
    assert mul(0x57, 0x13) == 0xfe


def test_mul_by_one_is_identity():
    assert mul(0x57, 0x01) == 0x57


def test_mul_by_two_equals_xtime():
    assert mul(0x57, 0x02) == xtime(0x57)
