# Authenticated-Diffie-Hellman-Key-Establishment-Protocol

Language Specification: Programs are written in Python 3.

# DESCRIPTION:
Aim is to establish 256-bit shared secret key between two processes in different machines or same machine with the help of Authenticated Diffie-Hellman key establishment protocol. 
The processes have a Diffie-Hellmann public and private key, and they want to establish a new shared secret key ensuring perfect forward secrecy. 
MAC function is used for authentication. An elliptic curve cryptography group E(GF(p)) (where p is a large prime number) is used, where Diffie-Hellman key establishment protocol can be run in a prime subgroup of the main group. 
The common key established in a separate window for each process is displayed with the time required to compute the key (excluding communication delay).

# EXECUTING THE PROGRAM:
- Before executing the programs, ensure that no other process is running on port 49175 of localhoast (or enter a free port number in line 53 of PrincipalA and line 58 of PrincipalB, both should be same!)
- Keep all 3 programs (data_and_utils.py, PrincipalA.py and PrincipalB.py) in same folder.
- If keeping PrincipalA and PrincipalB in different folders, then make sure that a copy of data_and_utils.py is present in both folders.
- First open one terminal for PrincipalA and use command: py PrincipalA.py
- Then open other terminal for PrincipalB and use command: py PrincipalB.py
(OR, double click on PrincipalA.py and run with Python3, then double click on PrincipalB and run with Python3 )

NOTE: Execution of PrincipalA should be started before executing PrincipalB


# ABOUT data_and_utils.py FILE:
- data_and_utils.py contains the public data about the Elliptic Curve.
- Along with this, it also contains definitions of some utility functions (ecc operations, timer, extended Euclid algo, hexadecimal conversion).


# ASSUMPTIONS:
- A shared secrect key initially exists between A and B. This key is used as authentication key. (line no. 14 in both codes)
(This key will be renewed and replaced using Deffie-Hellman key establishment protocol.)


# DETAILS OF EXECUTION:
- A & B will generate random (private, public) key pairs from E(GF(p)) defined in data_and_utils.py [ say (a, aG)  and (b, bG) respectively ]
- A will wait for connection
- B will connect to A
- A will send his public key (aG) with HMAC (using initial symmetric key)
- B will authenticate the received message
- If B authenticates message from A successfully only then B will send his public key (bG) to A
- A will authenticate the received message
- Only after successful authentication A will calculate new key [i.e. a(bG)]
- Simultaneoulsy B will also calculate new key [i.e. b(aG)]
- New key calculated by A and B will be printed on their respective terminals.
- connection between A and B will be closed
- A will wait for new connection 
[ note that now shared secret key is changed, so A cannot authenticate B with old key (without restarting), so to run B again (without restarting A, to check if new key was set in A) replace the old key in PrincipalB on line 14 with the newly generated key.]
[ Also, if you want A to refresh its private public key pair for every connection then uncomment the last line of PrincipalA.py. (If running A only once and B multiple times) ]


# EXPONENTIATION OPERATION (Point Multiplication in this case)
- Defined in data_and_utils.py file (line no. 126)
- Uses m-ary divide-and-conquer multiplication (here $m = 2^r, r$ can be changed on line number 128)
- Details of other functions are mentioned as docstrings below function names


### Close the terminals to stop execution.

### sample.png contains sample output of the execution
