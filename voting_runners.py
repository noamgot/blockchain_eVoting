import random
from typing import List, Set

from eth_typing import Address
from termcolor import cprint

from utils import TRUE_VOTES_DEBUG_DICT, NUM_VOTERS_PER_GROUP, STARS_LINE, split_list, NUM_VOTERS
from voting_classes import Candidate, Voter, CertificateAuthority, VotingError, VotingObject


class BasicVotingRunner:
    """
    This is the most basic scenario - we run a full voting procedure, where all parties are honest.
    """

    def __init__(self, num_voters: int, candidates: List[str]):
        cprint("***** The election begins! *****", "magenta")
        print(STARS_LINE)
        self.voting_objects_pool: Set[VotingObject] = set()
        candidates_indices = random.sample(range(num_voters), len(candidates))
        self.all_candidates: List[Candidate] = [Candidate(idx=idx, name=name) for (idx, name) in zip(candidates_indices, candidates)]
        cprint("The candidates are:", "yellow")
        cprint(str(self.all_candidates)[1:-1], "yellow")
        print(STARS_LINE)
        self.all_voters: List[Voter] = [Voter(i) for i in range(num_voters)]
        self.voters_groups: List[List[Voter]] = split_list(self.all_voters, NUM_VOTERS_PER_GROUP)
        print("The voters' groups are:")
        for i, group in enumerate(self.voters_groups):
            print(f"Group {i}: {group}")
        print(STARS_LINE)
        self.ca = CertificateAuthority(voters=self.all_voters, candidates=self.all_candidates,
                                       voting_groups=self.voters_groups)
        print(STARS_LINE)

    def _publish_candidates_public_keys(self, contract_address: Address):
        for candidate in self.all_candidates:
            candidate.set_contract(contract_address)
            candidate.deploy_public_key()

    def _run_single_group_voting(self, contract_address: Address, group: List[Voter], group_idx: int) -> VotingObject:
        cprint(f"***** Starting votes for group {group_idx} *****", "magenta")
        voting_object = self.ca.publish_voting_object(group_idx)
        for idx, voter in enumerate(group):
            voter.set_contract(contract_address)
            voter.set_voters(group, idx)
        first_voter = group[0]
        first_voter.shuffle_votes(voting_object)
        return voting_object

    def _sign_voting_object(self, group: List[Voter], group_idx: int, voting_object: VotingObject):
        cprint(f"***** Voters of group {group_idx} start signing the voting object *****", "magenta")
        for voter in group:
            voter.sign_on_voting_object(voting_object)
        self.ca.sign_on_voting_object(voting_object)
        self.voting_objects_pool.add(voting_object)

    def run(self):
        contract_address = self.ca.get_contract_address()
        self._publish_candidates_public_keys(contract_address)
        print(STARS_LINE)
        self.ca.start_voting_phase()
        print(STARS_LINE)
        self._run_all_groups_voting(contract_address)
        print(STARS_LINE)
        self._publish_voting_objects()
        print(STARS_LINE)
        self._run_vote_presence_validation()
        self.ca.start_reveal_phase()
        print(STARS_LINE)
        self._publish_candidates_private_keys()
        self.ca.close_vote()

        voting_results = self.ca.count_votes()
        for cand in [c.get_name() for c in self.all_candidates]:
            cprint(f"{cand} got {voting_results[cand]} votes (true votes: {TRUE_VOTES_DEBUG_DICT[cand]})", "green")

    def _run_all_groups_voting(self, contract_address: Address):
        for group_idx, group in enumerate(self.voters_groups):
            group_voting_object = self._run_single_group_voting(contract_address, group, group_idx)
            self._sign_voting_object(group, group_idx, group_voting_object)

    def _publish_candidates_private_keys(self):
        for candidate in self.all_candidates:
            cprint(f"{candidate} reveals its private key", "yellow")
            candidate.reveal_private_key()

    def _run_vote_presence_validation(self):
        cprint(f"***** Voters make sure that their votes made it into the contract *****", "magenta")
        for voter in self.all_voters:
            # reveal phase will not start if not all vote's appear on the blockchain
            print(f"{voter} checking...", end="")
            if voter.validate_vote_on_contract():
                print("OK.")
            else:
                raise VotingError(f"{voter}'s vote does not appear on the blockchain. something went wrong!!")
        cprint("***** All votes appear on the blockchain - starts revealing phase! *****", "magenta")

    def _publish_voting_objects(self):
        cprint(f"***** Voters publish their votes on the contract *****", "magenta")
        for voting_object in self.voting_objects_pool:
            group_idx = voting_object.get_group_idx()
            publisher = self.voters_groups[group_idx][0]
            print(f"{publisher} publishes the votes of group {group_idx}")
            publisher.publish_vote_to_contract(voting_object)


class VotingRunnerUnwantedGuest(BasicVotingRunner):
    """In this scenario, an unwanted user infiltrates the system and tries to participate in the voting (despite being an unauthorized voter)"""

    def __init__(self, num_voters: int, candidates: List[str]):
        super().__init__(num_voters, candidates)
        unwanted_guest = Voter(NUM_VOTERS)
        self.voters_groups[-1].append(unwanted_guest)
        self.ca.voting_objects[-1].voters_addresses.add(unwanted_guest.address.encode())


class VotingRunnerDoubleVote(BasicVotingRunner):
    """In this scenario, a voter of the first voting group tries to cheat and add an additional vote for his chosen candidate"""

    def _run_all_groups_voting(self, contract_address):
        for group_idx, group in enumerate(self.voters_groups):
            group_voting_object = self._run_single_group_voting(contract_address, group, group_idx)

            if group_idx == 0:
                # duplicate last vote before signing for group 0
                votes = group_voting_object.get_votes()
                fake_votes = votes + [votes[-1]]
                random.shuffle(fake_votes)
                group_voting_object.set_votes(fake_votes)
            self._sign_voting_object(group, group_idx, group_voting_object)
