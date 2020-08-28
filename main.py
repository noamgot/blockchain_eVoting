from termcolor import cprint
import colorama  # type: ignore

colorama.init()

try:
    from final_project.utils import CANDIDATES, NUM_VOTERS, STARS_LINE  # type: ignore
    from final_project.voting_runners import BasicVotingRunner  # type: ignore
except ModuleNotFoundError:
    from utils import CANDIDATES, NUM_VOTERS, STARS_LINE
    from voting_runners import BasicVotingRunner

if __name__ == '__main__':
    print(STARS_LINE)
    cprint(
        f"""This is the most basic scenario - we run a full vote procedure with {NUM_VOTERS} voters who choose one of {len(CANDIDATES)} candidates.""",
        "blue")
    print(STARS_LINE)
    voting_runner = BasicVotingRunner(NUM_VOTERS, CANDIDATES)
    voting_runner.run()
