---
layout: default
---

# Introduction
This is a final project done in the course "Introduction to Cryptographic Currencies" in the Hebrew University of Jerusalem.
The project was done together with Gili Lior. 

In this project we designed and implemented an e-voting system which is based on a dedicated blockchain, and using an Ethereum smart contract. The system is simulated via a python script that connects to a local Etherum blockchain running using Ganache. The smart contract was written in Solidity.

Here's a presentation describing the protocol and the general design choices we've made:

<iframe width="550" height="400" src="https://prezi.com/view/BelggHRsA2CRt6y3OObQ/embed" webkitallowfullscreen="1" mozallowfullscreen="1" allowfullscreen="1"></iframe>

A more detailed paper about this work can be found [here](https://noamgot.github.io/blockchain_eVoting/docs/Blockchain-based%20eVoting.pdf).


## About this demo
This demo contains 3 basic scenarios:
* `main.py` - A basic scenario where the election runs end to end with no actual problems - all players are honest.
* `main_unwanted_guest.py` - A scenario where an uneligible account joins the elections. This scenario crashes when the smart contract identifies the intfiltrator. 
* `main_double_vote.py` - A scenario where an eligible voter tries to vote twice. This scenario also crashes when the smart contract identifies the double voting. 
In all the scenarios we used 3 groups of 10 voters, but you can change these number to any other number (as long as there are enough Ganache accounts) in `utils.py`. In order to dig in to the details of how these scenarios actually work - check out the classes in `voting_runners.py`.


## Installation
In order to run this project, use python 3.7 (although probably most python 3.x version will work as well). You also must have [Ganace](https://www.trufflesuite.com/ganache) installed on your machine. 
No matter which operating system you use, make sure that:
* There are sufficient accounts (a 100 would be enough)
* You're listening on port 7545.

These 2 demands can be changed with corresponding changes in the code:
* For changing the amount of participants in the votes, change in the number of voters (`NUM_VOTERS` in `utils.py`). Notice that this variable is dependent on 2 other variables (`NUM_VOTING_GROUPS` and `NUM_VOTERS_PER_GROUP`), so you actually need to change these variables. Also, make sure that there's at least one extra account for the Certified Authority (CA).
* The listening port can be changed in `voting_classes.py` - change the number of port in this `w3 = Web3(HTTPProvider("http://127.0.0.1:7545"))` (replace 7545 with whatever port you choose). 

In order to make sure that you have all the needed packages, create a new virtual environment, and install the packages in the relevenat `reuirements_*.txt` file:
```bash
# choose either windows or linux
pip install requirements/requirements_<windows/linux>.txt
```
## Usage

### Windows
Launch a new local blockchain using Ganache (we used Ganache GUI). In windows, the default listening port is 7545, so you probably don't need to change anything.
Then, simply run one of the `main*.py`, e.g:
```bash
python main.py
```
and watch the output

### Linux
In a separate shell, launch a new local blockchain using Ganache:
```bash
module load ganache-cli
ganache-cli -a 100 -p 7545
```
Notice that we use 100 accounts (`-a 100`) and are listenting on port 7545 (`-p 7545`) as stated earlier. 

Then, **in a different shell**, simply run one of the `main*.py`, e.g:
```bash
python main.py
```
and watch the output

## License
[MIT](https://choosealicense.com/licenses/mit/)

## About the Authors
* [Gili Lior](https://www.linkedin.com/in/gili-lior-299636154/) - Computer Science B.Sc student at the Hebrew University of Jerusalem, Israel.
* [Noam Gottlieb](https://www.linkedin.com/in/noamgot/) - Computer Science M.Sc student at the Hebrew University of Jerusalem, Israel.
