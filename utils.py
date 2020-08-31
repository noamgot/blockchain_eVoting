from typing import List, Any

NUM_VOTING_GROUPS = 3
NUM_VOTERS_PER_GROUP = 10
NUM_VOTERS = NUM_VOTING_GROUPS * NUM_VOTERS_PER_GROUP
RSA_NUM_BITS = 1024
RSA_NUM_BYTES = int(RSA_NUM_BITS / 8)
RSA_MAX_DATA_SIZE = RSA_NUM_BYTES - 42

CANDIDATES = ['Alice', 'Bob', 'Charlie', 'Donna']
# probabilities of each candidate to be chosen. Change to get various election results!
CANDIDATES_WEIGHTS = [0.25, 0.25, 0.25, 0.25]
TRUE_VOTES_DEBUG_DICT = None  # {c: 0 for c in CANDIDATES}
STARS_LINE = "*" * 100


def split_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    This method splits an input list into sub-lists of size chunk_size
    :param lst: input list
    :param chunk_size: size of every sublist
    :return: a list of lists of size chunk_size
    """
    return list((lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)))
