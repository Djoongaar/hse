# Initial commit
def sum_distance(begin: int, end: int) -> int:
    """
    Function calculates sum of all integers inside given range
    :param begin: beginning of range
    :param end: end of the range
    :return: result
    """
    assert isinstance(begin, int), "<{}> should be integer".format(begin)
    assert isinstance(end, int), "<{}> should be integer".format(begin)

    if begin > end:
        begin, end = end, begin

    return sum(range(begin, end + 1, 1))
