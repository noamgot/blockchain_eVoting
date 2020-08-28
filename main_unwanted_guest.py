from termcolor import cprint
import colorama  # type: ignore

colorama.init()

try:
    from final_project.utils import CANDIDATES, NUM_VOTERS, STARS_LINE  # type: ignore
    from final_project.voting_runners import VotingRunnerUnwantedGuest  # type: ignore
except ModuleNotFoundError:
    from utils import CANDIDATES, NUM_VOTERS, STARS_LINE
    from voting_runners import VotingRunnerUnwantedGuest

if __name__ == '__main__':
    print(STARS_LINE)
    cprint(f"""In this scenario, an unwanted user infiltrates the system and tries to participate in the voting (despite being an unauthorized voter)""",
           "blue")
    print(STARS_LINE)
    voting_runner = VotingRunnerUnwantedGuest(NUM_VOTERS, CANDIDATES)
    voting_runner.run()
