import random
from typing import List, Optional, Dict, Tuple, Set

import ecdsa  # type: ignore
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from termcolor import cprint
from web3 import Web3, HTTPProvider
from web3.eth import HexStr
from eth_typing import Address

from utils import RSA_MAX_DATA_SIZE, RSA_NUM_BYTES, RSA_NUM_BITS, TRUE_VOTES_DEBUG_DICT, NUM_VOTING_GROUPS, CANDIDATES_WEIGHTS
from contract import ABI, compiled_contract

w3 = Web3(HTTPProvider("http://127.0.0.1:7545"))  # type: ignore


class VotingError(Exception):
    """ exception class for errors in the voting process """
    pass


class VotingObject:
    """
    This class is a single mixed vote. It contains several participant's votes, shuffled, so it cannot be
    determined which voter performed which vote.
    """

    def __init__(self, ca_address: str, group_idx: int, voters: List['Voter']):
        self._ca_address: str = ca_address
        self.group_idx: int = group_idx
        self.voters: List[Voter] = voters
        self.voters_addresses: Set[bytes] = {v.get_address().encode() for v in voters}
        self._votes: List[bytes] = []
        self._voters_signatures: Dict[int, bytes] = {}  # will be updated after voters approve that their vote appear
        self._ca_signature: Optional[HexStr] = None  # will be updated after the CA validate all voters and signatures

    def __repr__(self):
        return f"<Voting Object, group index: {self.group_idx}>"

    def get_votes(self) -> List[bytes]:
        """ returns the list of votes that are part of this mixed vote """
        return self._votes

    def get_voters(self) -> List['Voter']:
        """ returns the list of voters who vote using this voting object"""
        return self.voters

    def get_addresses_voters(self) -> Set[bytes]:
        """ returns a byte sequence that is the concatenation of all voters' addresses """
        return self.voters_addresses

    def get_group_idx(self) -> int:
        """ returns the group index of which this voting object is related to """
        return self.group_idx

    def set_votes(self, votes: List[bytes]):
        """ sets the list of votes that are part of this mixed vote, to the given list of votes """
        self._votes = votes

    def __bytes__(self):
        """ returns the bytes representation of this mix vote. It is a concatenation of all votes together """
        return b''.join(self._votes)

    def get_voters_signatures(self) -> Dict[int, bytes]:
        """ returns the list of signatures of the voters, signing on this mixed vote """
        return self._voters_signatures

    def add_voter_signature(self, voter_idx: int, voter_signature: bytes):
        """
        adds a single signature over this mixed vote.
        :param voter_idx: The index of the voter to add it's signature.
        :param voter_signature: The signature of the voter.
        """
        self._voters_signatures[voter_idx] = voter_signature

    def get_ca_address(self) -> str:
        """ returns the address of the CA that is in charge of the voting system """
        return self._ca_address

    def get_ca_signature(self) -> Optional[HexStr]:
        """ returns the signature of the CA over the mixed vote. This signature will be verified in contract """
        return self._ca_signature

    def set_ca_signature(self, signature: HexStr):
        """ sets the given signature to be the signature of the CA over the mixed vote """
        self._ca_signature = signature


class AbstractParty:
    """ This is an abstract class for an object that use RSA mechanism for encryption and decryption """

    def __init__(self, idx):
        self.address = w3.eth.accounts[idx]
        key = RSA.generate(RSA_NUM_BITS)
        self.public_key = key.publickey()
        self._private_key = key
        self.idx = idx
        self.contract = None

    def set_contract(self, contract_address: Address):
        """ initialize the contract from the given address """
        self.contract = w3.eth.contract(address=contract_address, abi=ABI)

    def get_idx(self) -> int:
        """ returns the registration index of this instance """
        return self.idx

    def get_address(self) -> str:
        """ returns the ganache address of this instance """
        return self.address

    def count_votes(self) -> Dict[str, int]:
        """
        A function that counts the final result according to the contract state.
        :return: A dictionary containing the final results.
        """
        votes = self.contract.functions.getAllVotes().call()
        all_candidates_names, all_decrypt_keys, str_sk_ca = self.contract.functions.getDecryptKeys().call()

        decrypt_key_ca = RSA.import_key(str_sk_ca)
        ca_cipher_decrypt = PKCS1_OAEP.new(decrypt_key_ca)
        all_cipher_decrypt_keys = [PKCS1_OAEP.new(RSA.import_key(sk)) for sk in all_decrypt_keys]

        results = {name: 0 for name in all_candidates_names}

        for vote in votes:

            try:
                shards = [vote[i: i + RSA_NUM_BYTES] for i in range(0, len(vote), RSA_NUM_BYTES)]
                decrypted_shards = [ca_cipher_decrypt.decrypt(s) for s in shards]
                partially_dec_vote = b''.join(decrypted_shards)
            except ValueError:
                print("vote was not encrypted with the CA public key, INVALID")
                continue

            for i, cipher_decrypt_cand in enumerate(all_cipher_decrypt_keys):
                try:
                    fully_dec_vote = cipher_decrypt_cand.decrypt(partially_dec_vote)
                    cand_name_in_vote = fully_dec_vote[:16].decode().strip()
                    if all_candidates_names[i] == cand_name_in_vote:
                        results[all_candidates_names[i]] += 1
                        break
                except ValueError:
                    continue

        return results


class Candidate(AbstractParty):
    """ This class represents a candidate in the elections """

    def __init__(self, idx, name):
        super().__init__(idx)
        self.name = name

    def deploy_public_key(self):
        """
        The candidate deploys it's public key to the contract, so that all voters can encrypt their votes
        with this key.
        """
        cprint(str(self) + " deploying public key to the contract", "yellow")
        txn_dict = {'from': self.address}
        pk_to_export = self.public_key.export_key()
        self.contract.functions.addCandidateEncryptKey(pk_to_export).transact(txn_dict)

    def reveal_private_key(self):
        """
        Once the voting process is over, the candidate deploys it's private key so all the votes can be
        decrypted.
        """
        txn_dict = {'from': self.address}
        sk_to_export = self._private_key.export_key()
        self.contract.functions.publishCandidateDecryptKey(sk_to_export).transact(txn_dict)

    def get_name(self) -> str:
        """ returns the candidate's name """
        return self.name

    def __repr__(self):
        return f"<Candidate {self.idx} ({self.name})>"


class Voter(AbstractParty):
    """ This class represents a voter in the elections """

    def __init__(self, idx):
        AbstractParty.__init__(self, idx)
        self.voters: List['Voter'] = []  # the voters that cooperate with this voter for the mixed vote
        self._encrypted_vote: Optional[bytes] = None
        self._signing_key = ecdsa.SigningKey.generate()
        self.verifying_key = self._signing_key.get_verifying_key().to_der()

    def _sign(self, data: bytes) -> bytes:
        """ returns the voter's signature over the given data """
        signature = self._signing_key.sign(data)
        return signature

    def get_verifying_key(self) -> bytes:
        """ returns the verifying key of this voter, for signature verification"""
        return self.verifying_key

    def get_public_key(self) -> RSA.RsaKey:
        """ returns the public key of this instance """
        return self.public_key

    @staticmethod
    def encrypt(msg: bytes, public_key: RSA.RsaKey) -> bytes:
        """
        Encrypts a given message using a given public key.
        :param msg: The message to encrypt.
        :param public_key: The public key to encrypt with.
        :return: The encrypted message.
        """
        shards = [msg[i: i + RSA_MAX_DATA_SIZE] for i in range(0, len(msg), RSA_MAX_DATA_SIZE)]
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_shards = [cipher_rsa.encrypt(s) for s in shards]
        encrypted_msg = b''.join(encrypted_shards)
        return encrypted_msg

    def decrypt(self, cipher: bytes) -> bytes:
        """
        Trying to decrypt a message, using the instance's private key.
        :param cipher: The message to decrypt.
        :return: The decrypted message if the decryption succeeded. Else, returns None.
        """
        shards = [cipher[i: i + RSA_NUM_BYTES] for i in range(0, len(cipher), RSA_NUM_BYTES)]
        try:
            decrypt_key = PKCS1_OAEP.new(self._private_key)
            decrypted_shards = [decrypt_key.decrypt(s) for s in shards]
        except ValueError:
            raise VotingError
        m = b''.join(decrypted_shards)
        return m

    def __repr__(self):
        return f"<Voter {self.idx}>"

    def set_voters(self, voters: List['Voter'], voter_idx_in_group: int):
        """ sets the list of voters that cooperate with this voter in the mixed vote """
        self.voters = voters[voter_idx_in_group + 1:]

    def encrypt_vote(self) -> bytes:
        """
        Encrypts the voters vote with the candidate public key, and after that performs a chain encryption
        with the other voters' public keys.
        The encrypted message is in this form:
        'voter_i+1_pk(...(voter_n-1_pk(voter_n_pk(candidate_pk(vote_i))))...)'
        :return: The encrypted message
        """
        all_candidates_names, all_public_keys, str_public_key_ca = self.contract.functions.getEncryptKeys().call()
        cand_name = random.choices(all_candidates_names, weights=CANDIDATES_WEIGHTS)[0]
        if TRUE_VOTES_DEBUG_DICT is not None:
            TRUE_VOTES_DEBUG_DICT[cand_name] += 1
            print(f"{self} voted to {cand_name}")
        else:
            print(f"{self} voted")
        cand_index = all_candidates_names.index(cand_name)
        str_cand_pk = all_public_keys[cand_index]
        cand_pk = RSA.import_key(str_cand_pk)
        public_key_ca = RSA.import_key(str_public_key_ca)

        msg_to_encrypt = cand_name.ljust(16).encode() + get_random_bytes(48)  # 384 bit random string (nonce)
        m = self.encrypt(msg_to_encrypt, cand_pk)
        m = self.encrypt(m, public_key_ca)
        self._encrypted_vote = m  # save vote for the validation phase later
        print(f"{self} encrypting its vote...", end="")
        for voter in reversed(self.voters):
            # The chain encryption
            pk = voter.get_public_key()
            m = self.encrypt(m, pk)
        print("Done.")
        return m

    def shuffle_votes(self, voting_object: VotingObject) -> VotingObject:
        """
        The implementation of the mixing protocol - the voter decrypts one layer of the chained encryption of
        other voters from his group, encrypt his own vote with the next voters in group public keys, and shuffles
        the votes so it's hard to link between a voter and his vote.
        He sends the voting object to the next voter in chain.
        :param voting_object: The voting object of the mixed votes that the voter performs the protocol on.
        :return: The voting object that is returned from the next voter in chain.
        """
        votes_lst = voting_object.get_votes()
        for i, vote in enumerate(votes_lst):
            votes_lst[i] = self.decrypt(vote)
        encrypted_vote = self.encrypt_vote()
        votes_lst.append(encrypted_vote)
        random.shuffle(votes_lst)
        voting_object.set_votes(votes_lst)
        if not self.voters:  # the last user exposes the votes list
            return voting_object
        next_voter = self.voters[0]
        return next_voter.shuffle_votes(voting_object)

    def sign_on_voting_object(self, voting_object: VotingObject):
        """
        The voter sign's over the mixed vote, if his encrypted vote appears in it, and update the voting object with
        his signature.
        :param voting_object: The voting object that contains all votes.
        """
        all_votes = voting_object.get_votes()
        if self._encrypted_vote in all_votes:
            print(f"{self} signs on the voting object")
            all_votes_str = bytes(voting_object)
            signature = self._sign(all_votes_str)
            voting_object.add_voter_signature(self.idx, signature)
        else:
            print(f"The vote of {self} was not found in the votes list - hence, he did not sign the voting object!")

    def publish_vote_to_contract(self, voting_object: VotingObject):
        """
        This method deploys the mixed vote to the smart contract.
        :param voting_object: The voting object to deploy.
        """
        id_votes = id(voting_object)
        votes = voting_object.get_votes()
        ca_signature = voting_object.get_ca_signature()
        assert ca_signature is not None  # to satisfy mypy :)
        v, r, s = CertificateAuthority.get_v_r_s(ca_signature)
        txn_dict = {'from': self.address}
        self.contract.functions.addShuffledVoting(votes, id_votes, list(voting_object.get_addresses_voters()), v, r, s).transact(txn_dict)

    def validate_vote_on_contract(self) -> bool:
        """
        :return: True iff the voter's encrypted vote appears on the blockchain, and thus will be counted.
        """
        votes = self.contract.functions.getAllVotes().call()
        return self._encrypted_vote in votes


class CertificateAuthority(AbstractParty):
    """
    This class represents the organizer of the elections. He is in charge of validating the voters and the
    votes, and publish the final results.
    """

    def __init__(self, voters: List[Voter], candidates: List[Candidate], voting_groups: List[List[Voter]]):
        AbstractParty.__init__(self, idx=-1)
        self.voters: List[Voter] = voters
        self.candidates: List[Candidate] = candidates
        self.voting_objects: List[VotingObject] = self._generate_voting_objects(voting_groups)
        self._deploy_voting_contract()

    def _deploy_voting_contract(self):
        """
        This function deploys the voting contract.
        :param candidates: The list of candidates that participate in these elections.
        :return: The deployed contract
        """
        cprint(str(self) + ": deploying contract", "cyan")
        bd_channel_contract_factory = w3.eth.contract(abi=ABI, bytecode=compiled_contract['object'])
        txn_dict = {'from': self.address}
        voters_add = [voter.get_address().encode() for voter in self.voters]
        candidates_add = [cand.get_address() for cand in self.candidates]
        candidates_names = [cand.get_name() for cand in self.candidates]
        tx_hash = bd_channel_contract_factory.constructor(voters_add, candidates_add, candidates_names,
                                                          self.public_key.export_key()).transact(txn_dict)
        tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
        contract = w3.eth.contract(address=tx_receipt.contractAddress, abi=ABI)
        self.contract = contract

    def get_contract_address(self) -> Address:
        """ returns the ganache address of the voting contract """
        return self.contract.address

    def start_voting_phase(self):
        """ sets the status of the voting contract to Voting """
        txn_dict = {'from': self.address}
        self.contract.functions.allowVoting().transact(txn_dict)
        cprint(str(self) + ": all candidates published their encryption keys - the voting phase begins!", "cyan")

    def start_reveal_phase(self):
        """ sets the status of the voting contract to Reveal (candidates reveal their private keys) """
        txn_dict = {'from': self.address}
        self.contract.functions.allowRevealKeys().transact(txn_dict)

    def close_vote(self):
        """ sets the status of the voting contract to Close """
        txn_dict = {'from': self.address}
        self.contract.functions.closeVote(self._private_key.export_key()).transact(txn_dict)
        print("All decryption keys are published, the vote is closed.")

    def publish_voting_object(self, group_idx) -> VotingObject:
        """ initialize a VotingObject and returns it """
        voting_object = self.voting_objects[group_idx]
        return voting_object

    def sign_on_voting_object(self, voting_object: VotingObject):
        """ if all voters of a voting object are valid, the CA signs over the votes """
        if self.address != voting_object.get_ca_address():
            raise VotingError("Voting object CA address mismatch!")
        all_votes_str = bytes(voting_object)
        self._validate_voters(all_votes_str, voting_object)
        # at this point - all voters signed the voting object, and their signatures are valid
        cprint(f"{self}: The voting object of group {voting_object.get_group_idx()} is valid and signed by the CA", "cyan")
        concatenated_addresses = b''.join(voting_object.get_addresses_voters())
        signature = self.sign_web3(all_votes_str, id(voting_object), concatenated_addresses)
        voting_object.set_ca_signature(signature)

    def sign_web3(self, all_votes_str: bytes, voting_object_id: int, voters_addresses: bytes) -> HexStr:
        """
        preforms CA signature over the votes data.
        :param all_votes_str: A concatenated bytes of all votes.
        :param voting_object_id: The id of the voting object.
        :param voters_addresses: Concatenated bytes of all the voters addresses that participated in this VotingObject.
        :return: The CA's web3 signature over the votes and the voting object id
        """
        message_hash = Web3.soliditySha3(['bytes', 'uint256', 'bytes'],
                                         [all_votes_str, voting_object_id, voters_addresses])
        return w3.eth.sign(self.address, message_hash)

    @staticmethod
    def get_v_r_s(sig: HexStr) -> Tuple[int, str, str]:
        """ Converts the signature to a format of 3 numbers v,r,s that are accepted by ethereum """
        return Web3.toInt(sig[-1]) + 27, Web3.toHex(sig[:32]), Web3.toHex(sig[32:64])

    @staticmethod
    def _validate_voters(all_votes_str: bytes, voting_object: VotingObject):
        """
        The CA validates that all voters that are part of this VotingObject group are eligible to vote, and
        their votes are valid.
        :param all_votes_str: The concatenated bytes of all the votes of the given VotingObject.
        :param voting_object: the VotingObject to validate it's voters.
        :raise: If something is invalid, raises VotingError.
        """
        voters_signatures = voting_object.get_voters_signatures()
        group_voters = voting_object.get_voters()
        all_addresses = set()
        for voter in group_voters:
            voter_idx = voter.get_idx()
            if voter_idx not in voters_signatures:
                raise VotingError(f"Voter {voter_idx} did not sign the voting object")
            voter_signature = voters_signatures[voter_idx]
            voter_verifying_key = voter.get_verifying_key()
            try:
                ecdsa.VerifyingKey.from_der(voter_verifying_key).verify(voter_signature, all_votes_str)
            except ecdsa.keys.BadSignatureError:
                raise VotingError(f"Signature mismatch for voter {voter_idx}")
            all_addresses.add(voter.get_address().encode())
        if all_addresses != voting_object.get_addresses_voters():
            raise VotingError(f"Given voters addresses mismatch")

    def __repr__(self):
        return f"<Certificate Authority>"

    def _generate_voting_objects(self, voting_groups: List[List[Voter]]) -> List[VotingObject]:
        """ generates all voting objects according to the given groups """
        voting_objects = [VotingObject(self.address, i, voting_groups[i]) for i in range(NUM_VOTING_GROUPS)]
        return voting_objects
