*Disclaimer: I did not finish this challenge during the competition because I could not make the final step. 
However, I feel that the approach used is worth writing up. In fixing this issue, [A*0*E's writeup](https://github.com/A-0-E/writeups/blob/master/spamandflags-2020/README.md) was very helpful.*

# OTS

*By [@HydraulicSheep](https://github.com/HydraulicSheep) from [Pennant Tellers](https://ctftime.org/team/116481)*

This challenged revolved around the idea of '[One Time Signatures](https://en.wikipedia.org/wiki/Lamport_signature)' (although I don't think this used a real-world algorithm given the serious flaw). We were given a message, signature and public key. To get the flag, we had to forge a message containing the word 'flag'.

Using the code returned by the server, we found a clear exploit:

As the initial numbers were hashed a number of times based on the encoded byte, and we were given the original message, a signature could be forged by hashing certain bytes further, changing them to signed bytes of higher value.

However, the MD5 checksum at the end of the message still needed to match the new forged bytes. To do this, I employed two techniques:

1. Searching for messages with low MD5 checksums matching our constraints. This was modelled using a translated sigmoid function to ensure that bumping up low bytes was prioritised over getting very high values. However, this search was flawed as I wrote it quickly without much thought.

2. Picking a relatively good message and bruteforcing. This is the step I didn't achieve properly during the CTF. I didn't consider getting lucky to be possible without a very good hash so I didn't even try it. However, this turned out to be easier than expected.

So, the now-working code is attached at [OTS.py](spamandflags/OTS.py).

Thanks to SpamandHex for a great CTF!

