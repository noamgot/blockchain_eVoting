from termcolor import cprint
import colorama  # type: ignore

from utils import CANDIDATES, NUM_VOTERS, STARS_LINE
from voting_runners import VotingRunnerDoubleVote

colorama.init()

if __name__ == '__main__':
    print(STARS_LINE)
    cprint(
        f"""In this scenario, a voter of the first voting group tries to cheat and add an additional vote for his chosen candidate""",
        "blue")
    print(STARS_LINE)
    voting_runner = VotingRunnerDoubleVote(NUM_VOTERS, CANDIDATES)
    voting_runner.run()
