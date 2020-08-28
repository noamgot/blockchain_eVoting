pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

contract VotingContract {

    enum VotingStatus {REGISTRATION, VOTING, REVEAL_KEYS, CLOSED}

    address public owner;
    VotingStatus private status;
    bytes[] public final_votes;
    address[] public candidates_add;
    mapping(address => bool) public candidates_exist;
    mapping(bytes => bool) public voters_allowed_to_vote;
    mapping(address => string) public candidates_encrypt_keys;
    mapping(address => string) public candidates_decrypt_keys;
    string[] public candidates_names;
    uint cand_length;
    string private CAEncryptKey;
    string private CADecryptKey;


    modifier onlyOwner{
        require(msg.sender == owner,
            "Only an owner (CA) can call this function.");
        _;
    }

    modifier onlyCandidate{
        require(candidates_exist[msg.sender],
            "This method can only be executed by candidates");
        _;
    }

    modifier isRegistration{
        require(status == VotingStatus.REGISTRATION,
            "The voting should be in registration.");
        _;
    }

    modifier isVoting{
        require(status == VotingStatus.VOTING,
            "The voting should be open.");
        _;
    }

    modifier isClosed{
        require(status == VotingStatus.CLOSED,
            "The voting should be closed.");
        _;
    }

    modifier isRevealPhase{
        require(status == VotingStatus.REVEAL_KEYS,
            "Should be in reveal-keys status.");
        _;
    }

    constructor(bytes[] memory voters_addresses, address[] memory cands_addresses, string[] memory names, string memory ca_enc_key) public {
        // require(addresses.length == names.length, "names and addresses must be in the same length");
        owner = msg.sender;
        status = VotingStatus.REGISTRATION;
        candidates_add = cands_addresses;
        cand_length = cands_addresses.length;
        candidates_names = names;
        CAEncryptKey = ca_enc_key;

        for (uint i = 0; i < cand_length; i++) {
            candidates_exist[candidates_add[i]] = true;
        }

        for(uint i = 0; i < voters_addresses.length; i++) {
            voters_allowed_to_vote[voters_addresses[i]] = true;
        }
    }

    function addCandidateEncryptKey(string calldata encryption_key) isRegistration onlyCandidate external {
        candidates_encrypt_keys[msg.sender] = encryption_key;
    }

    function allowVoting() onlyOwner isRegistration external {
        for (uint i = 0; i < candidates_add.length; i++) {
            // validate that all candidates published their public keys
            if (keccak256(abi.encodePacked(candidates_encrypt_keys[candidates_add[i]])) == keccak256(abi.encodePacked(""))) {
                revert();
            }
        }
        status = VotingStatus.VOTING;
        // the CA changes the voting status so everyone can vote
    }

    function allowRevealKeys() onlyOwner isVoting external {
        status = VotingStatus.REVEAL_KEYS;
        // the CA changes the voting status so candidates reveal their keys
    }

    function addShuffledVoting(bytes[] calldata shuffled_votes, uint votes_id, bytes[] calldata voters_addresses,
        uint8 v, bytes32 r, bytes32 s) isVoting external {
        bytes memory concatenated_votes = '';
        bytes memory concatenated_addresses = '';
        for (uint i = 0; i < shuffled_votes.length; i++) {
            concatenated_votes = abi.encodePacked(concatenated_votes, shuffled_votes[i]);
            concatenated_addresses = abi.encodePacked(concatenated_addresses, voters_addresses[i]);
        }
        if (!verifySig(concatenated_votes, votes_id, concatenated_addresses, v, r, s)) {  // verify CA signature
            revert();
        }

        for (uint i = 0; i < voters_addresses.length; i++) {
            // make sure that the voter is allowed to vote
            // (i.e, that he's a valid voter that has not voted yet)
            if (voters_allowed_to_vote[voters_addresses[i]] == false) {
                revert();
            }
            // voter voted - set to false to prevent a second vote
            voters_allowed_to_vote[voters_addresses[i]] = false;
        }

        for (uint i = 0; i < shuffled_votes.length; i++) {
            final_votes.push(shuffled_votes[i]);
        }
    }

    function publishCandidateDecryptKey(string calldata decryption_key) isRevealPhase onlyCandidate external {
        candidates_decrypt_keys[msg.sender] = decryption_key;
    }

    function closeVote(string calldata ca_decrypt_key) isRevealPhase onlyOwner external {
        for (uint i = 0; i < candidates_add.length; i++) {
            // validate that all candidates published their public keys
            if (keccak256(abi.encodePacked(candidates_decrypt_keys[candidates_add[i]])) == keccak256(abi.encodePacked(""))) {
                revert();
            }
        }
        CADecryptKey = ca_decrypt_key;
        status = VotingStatus.CLOSED;
    }

    function verifySig(bytes memory concat_votes, uint votes_id, bytes memory concat_addresses,
        uint8 v, bytes32 r, bytes32 s) view public returns (bool) {
        // v,r,s are the signature.
        // signerPubKey is the public key of the signer (this is what we validate the signature against)
        // balance, serial_num constitute the message to be signed.

        // the message is made shorter by hashing it:
        bytes32 hashMessage = keccak256(abi.encodePacked(concat_votes, votes_id, concat_addresses));

        //message signatures are prefixed in ethereum.
        bytes32 messageDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hashMessage));
        //If the signature is valid, ecrecover ought to return the signer's pubkey:
        return ecrecover(messageDigest, v, r, s) == owner;
    }

    function getEncryptKeys() isVoting view external returns (string[] memory, string[] memory, string memory) {
        string[] memory ret = new string[](cand_length);
        for (uint i = 0; i < cand_length; i++) {
            ret[i] = candidates_encrypt_keys[candidates_add[i]];
        }
        return (candidates_names, ret, CAEncryptKey);
    }

    function getDecryptKeys() isClosed view external returns (string[] memory, string[] memory, string memory) {
        string[] memory ret = new string[](cand_length);
        for (uint i = 0; i < cand_length; i++) {
            ret[i] = candidates_decrypt_keys[candidates_add[i]];
        }
        return (candidates_names, ret, CADecryptKey);
    }

    function getAllVotes() view external returns (bytes[] memory) {
        return final_votes;
    }

}