# Crypto-01
*By Meatspace Men ([@lduck1107](https://github.com/lduck11007) and [HydraulicSheep](https://github.com/HydraulicSheep))*

This challenge, as one of the few our team could solve in the 2020 White Hat Grand Prix, saw us taking an approach that was by no means expected.

The ‘CHAOS’ encryption tool output a key and options upon netcatting in:

```
1.Send some input
2.Submit the key
````

After some playing around with random keyboard-mashing (One of many ‘professional’ skills in our toolbelt), some patterns began to emerge. 

Observations:
1.	Each character corresponded to a short string of numbers and letters (which looked like some form of hexadecimal as letters seemed to precede ‘f’ in the alphabet)
2.	Of uppercase letters, lowercase letters, numbers and misc. characters, each message was of different length. 
3.	Each type of character only affected one 4-character part of the output. For instance, the encryptions of ‘A’ and ‘B’ would only differ by 4 characters while the rest would stay constant. And each character 
4.	Messages of different lengths would not have the same  ‘encryptions’ for the same characters but messages of the same length would.

To be honest, in retrospect, there probably was some common cipher being implemented here (e.g. a numerical method or substitution) but us Meatspace Men sure didn’t spot it.

Instead, we wrote [a script](https://github.com/HydraulicSheep/ctfs/blob/master/whitehatgrandprix/crypto01.py) to input a string of each character with the same length as the key. Per observations 3 and 4, this would allow us to compare each block in the output with its corresponding place in the key: If they were the same then (BINGO!) we had a match.

The script iterated through all allowed characters before inputting the deduced key.

And Voila! 

```
KEY: Hav3_y0u_had_4_h3adach3_4ga1n??_Forgive_me!^^
```

Another flag captured! (Just as intended….)
