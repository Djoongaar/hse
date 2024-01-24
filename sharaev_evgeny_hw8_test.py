from sharaev_evgeny_hw8 import sum_distance


def test_sum_distance(a, b, c):
    assert sum_distance(a, b) == sum_distance(b, a) == c


test_sum_distance(3, 1, 6)
test_sum_distance(7, 7, 7)
test_sum_distance(1, 0, 1)
test_sum_distance(0, 0, 0)
test_sum_distance(-5, 0, -15)
# Broken assert
# test_sum_distance(-5, 0, 10)
