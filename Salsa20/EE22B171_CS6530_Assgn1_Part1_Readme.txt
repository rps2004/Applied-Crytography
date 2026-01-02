==================================================
Part 1: Salsa20: Diffusion Analysis
==================================================

==================================================
README: Salsa20 Diffusion Analysis
==================================================

This file documents the analysis and experimentation performed on the Salsa20 stream cipher.  
It covers the following aspects:

1. How to Run
   - Instructions to run the Python3 implementation of Salsa20.
   - Commands include generating keystream, encrypting/decrypting files,
     performing differential analysis, and using parallel execution.

2. Differential Analysis
   - Compares the internal states of Salsa20 for different counter values.
   - Shows how a small change in the counter propagates through the 4x4 state matrix.
   - Confirms the Avalanche Effect and illustrates how diffusion spreads over multiple double rounds.

3. Parallelism in Quarter-Rounds
   - Demonstrates use of Python's ThreadPoolExecutor to parallelize quarter-round computations.
   - Provides timing observations and discussion about Python threading overhead.

4. Diffusion Discussion
   - Analysis of how differences propagate in Salsa20 rounds.
   - Observations about full diffusion, pseudorandomness, and keystream independence.

Notes:
- The EE22B171_CS6530_Assgn1_Part1.txt is 68 KB and contains the analysis of both counter : 0 Vs 1 and 71 Vs 72.
- All analysis uses default key, nonce, and counter (all zeros) unless specified.
- Differential analysis is performed between selected counter values to study diffusion behavior.
- Execution times are recorded to provide performance insights.


1. How to Run
-------------
The code is written in Python3. To run the Salsa20 implementation:
  
    python salsa20.py --keystream
    python salsa20.py --enc --in input.txt --out encrypted.bin
    python salsa20.py --dec --in encrypted.bin --out output.bin
    python salsa20.py --diff 0 1
    python salsa20.py --diff 71 72
    python salsa20.py --keystream --parallel
    python salsa20.py --keystream --log dr [log file will be created that contains all the double round].
    

Notes:
- By default, the key, nonce, and counter are set to all zeros.
- The --diff option generates a differential analysis file that shows
  how the state changes round by round.
- The quarter round can be dumped in the log file by using --log dr+qr.
- The total file size of EE22B171_CS6530_Assgn1_Part1.txt is 68 KB.

2. Differential Analysis: Counter 0 vs Counter 1
------------------------------------------------
- Input: Key = 32-byte all zeros, Nonce = 8-byte all zeros.
- Command: python salsa20.py --diff 0 1
- This command will take 0 and 1 as counter and perform the differential analysis.
- Comparison of states between counter = 0 and counter = 1.


Initial State
61707865 00000000 00000000 00000000   61707865 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000000 3320646e 00000000 00000000   00000000 3320646e 00000000 00000000   00000000 00000000 00000000 00000000
00000000 00000000 79622d32 00000000   00000001 00000000 79622d32 00000000   00000001 00000000 00000000 00000000
00000000 00000000 00000000 6b206574   00000000 00000000 00000000 6b206574   00000000 00000000 00000000 00000000
After DR1
f1e35811 a40114dd 218dc5bd 4b61e284   6f01b346 a201161d 398f4eb1 9cab6147   9ee2eb57 060002c0 18028b0c d7ca83c3
be4befd4 3fdfeb9f 7b756e86 6faac538   be4befd4 3fdfeb9f 7b756e86 6faac538   00000000 00000000 00000000 00000000
acdd42de 1b6b1a1b c8248ce8 bb3717eb   acdd42df 1b6b7a1b 48288ceb bb3717eb   00000001 00006000 800c0003 00000000
eeb3332a 68c62f5b 9d4633d3 0c8bdd57   eeb3132a 68862f5b 994633db 0cebc257   00002000 00400000 04000008 00601f00
After DR2
bad8bd7e 2d37e3c1 2c0e2dae 6836a8cf   4ebbc878 e4b8e9f9 2b10b289 be5601da   f4637506 c98f0a38 071e9f27 d660a915
7aff5dae dad670cf 15919d66 66c2e223   aff85206 034ae3c7 045e872c 2b87d758   d5070fa8 d99c9308 11cf1a4a 4d45357b
98798076 4b0f515e e6939f84 112b86ad   29b32dfd 3aae698f a2c571c0 45735c31   b1caad8b 71a138d1 4456ee44 5458da9c
bc33c994 86c7b0ab 3efc6cad 62eb5022   d2fb4a0f c3b04e69 24b499ef 7ec160b8   6ec8839b 4577fec2 1a48f542 1c2a309a
After DR3
6f12e095 8944477f 7ba263d9 b636cfe9   8598a227 c19554d3 efa2d114 a0b4831f   ea8a42b2 48d113ac 9400b2cd 16824cf6
1b1e8485 59a7b18f c6e1c9df b9a57333   c6969f34 f9765ce7 bf3f4fe4 b5d64758   dd881bb1 a0d1ed68 79de863b 0c73346b
8ca96595 baf7e388 d844b7da 49ee5102   5323a789 f8d1dab2 b90a32dc 472a7541   df8ac21c 4226393a 614e8506 0ec42443
e355ed89 5624d700 74f33efc 584d2271   b4a098bd 82d270e0 d47b4952 2d5a1916   57f57534 d4f6a7e0 a08877ae 75173b67
After DR4
43ace13a 54239cf9 8691ea45 1b68ad6e   7013424d ce443e7e 88fe4dbb b374824d   33bfa377 9a67a287 0e6fa7fe a81c2f23
fa4f7c97 dc570895 419da7bc 784101fb   8fcdb26f 64135362 f018f147 0a19bceb   7582cef8 b8445bf7 b18556fb 7258bd10
31cf8ecf 7de7e564 887a6842 db1e0895   d200e660 6b298bf6 d5c4a0e5 8ec7caa4   e3cf68af 16ce6e92 5dbec8a7 55d9c231
a1c8452f ec2b7db1 9feff38d 0a5ffc43   6305ca4b c7e7b6ef 409d6c33 825011fe   c2cd8f64 2bcccb5e df729fbe 880fedbd

- Observations:

At the Initial State, the only difference between counter=0 and counter=1
appears in the counter word of the state matrix (one 32-bit word changed).

After Double Round 1:
- The differences begin to spread but remain localized to certain columns
  and a few rows. We can still see that not all state words are affected.
- This shows that Salsa20 does not achieve full diffusion in just one round.

After Double Round 2:
- More state words start to differ, and the differences propagate into
  diagonal positions. Now, differences are present in almost every row,
  although some symmetry remains.

After Double Round 3:
- The differences are spread across nearly the entire 4x4 matrix.
- Most words are affected, with no obvious pattern left.
- This shows that diffusion is now strong and nonlinear effects dominate.

After Double Round 4:
- Complete diffusion is achieved. Almost all state words have diverged
  significantly, and the outputs are fully uncorrelated.
- From this point onward, the keystreams of counter=0 and counter=1 are
  entirely distinct and pseudorandom.

Summary:
- Confirms Avalanche Effect.
- Diffusion begins slowly in Salsa20, with the first round only affecting
  specific columns and rows.
- By the 3rd and 4th double rounds, the entire state is randomized and
  differences from the counter propagate everywhere.
- This confirms that Salsa20 requires multiple rounds to achieve strong
  diffusion, but once reached, the keystream blocks become fully distinct.

- Execution time recorded: [0.0051980 seconds].


3. Differential Analysis: Counter 71 vs Counter 72
--------------------------------------------------
- Same key and nonce as above.
- My roll number: EE22B171,Hence the counter values are initialised 71 and 72.
- Command: python salsa20.py --diff 71 72 
- Initial states differ only in the counter value.

Initial State
61707865 00000000 00000000 00000000   61707865 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000000 3320646e 00000000 00000000   00000000 3320646e 00000000 00000000   00000000 00000000 00000000 00000000
00000047 00000000 79622d32 00000000   00000048 00000000 79622d32 00000000   0000000f 00000000 00000000 00000000
00000000 00000000 00000000 6b206574   00000000 00000000 00000000 6b206574   00000000 00000000 00000000 00000000
After DR1
0697f614 2601049f 266c81a7 20fa73b8   d98a2dda d40106dc 7e68121b b32c5078   df1ddbce f2000243 580493bc 93d623c0
be4befd4 3fdfeb9f 7b756e86 6faac538   be4befd4 3fdfeb9f 7b756e86 6faac538   00000000 00000000 00000000 00000000
acdd4299 1b62ba1b 49108d36 bb3717eb   acdd4296 1b621a1b c9048d34 bb3717eb   0000000f 0000a000 80140002 00000000
ee8bd32a da062f5b f146202e be14e857   ee8a332a dec62f5b bd462096 bff5b557   0001e000 04c00000 4c0000b8 01e15d00
After DR2
f92053b1 a9908a91 87b64b3e 5c43b4ac   9a33d4a9 f0f661fc 7f12c19a 01383f44   63138718 5966eb6d f8a48aa4 5d7b8be8
927ea3b4 88af42f6 775ec709 21772785   ac2eea59 dc21e5c1 8a94c3b7 b4b3fef5   3e5049ed 548ea737 fdca04be 95c4d970
a04e1f4a 5ff1716d 9f35a7a6 01d78814   6764453e 8bb6d913 b4fe4ab4 8ca6c031   c72a5a74 d447a87e 2bcbed12 8d714825
c5e11692 2f8cf52b 72cc40e1 94adb677   75428ada b23a58d9 1dcd995b be59a22f   b0a39c48 9db6adf2 6f01d9ba 2af41458
After DR3
670b20ea 3b9436ec 7698e18c bdd3e722   9aa2f585 36572e2f 4eb658d6 31e9bfc0   fda9d56f 0dc318c3 382eb95a 8c3a58e2
5ec69154 1913a18f ca2eddc5 cfcb82a3   f7ac5dc8 96459945 a04f228a 1067e2e1   a96acc9c 8f5638ca 6a61ff4f dfac6042
74668c9a 85eb9457 a10df646 c0b7a347   26eab6f9 a101b976 44dc55e3 cd327dac   528c3a63 24ea2d21 e5d1a3a5 0d85deeb
1445cd0a 85854a56 5a170453 5b695a5a   506effc6 27b3fe25 8bf7c3c0 4a1be730   442b32cc a236b473 d1e0c793 1172bd6a
After DR4
db0f56f4 3e84e1ed fabea2ed dd367084   2ccd16f2 1c47457a c56597bc 0d7d0dfe   f7c24006 22c3a497 3fdb3551 d04b7d7a
5809d485 ff543394 03bf278c fba64e41   8b9d89c9 30e96fb6 e2e45c79 acc349e2   d3945d4c cfbd5c22 e15b7bf5 576507a3
00e53e5c c4edb376 ac4563dd d37358f4   8a2128fb 09239259 f5d333ee 002e0911   8ac416a7 cdce212f 59965033 d35d51e5
3ba87f00 ff7fbba6 c329c683 d3dabd52   db023e2b cc49ca45 9f45e1db 6a518d1a   e0aa412b 333671e3 5c6c2758 b98b3048

- After 4th double rounds, the difference spreads to all state words, that is there is complete diffusion.
- Execution time: [0.0051987 seconds].
- Observations:
  * Confirms avalanche effect.
	
  * Each block of Salsa20 is independent; changing the counter produces
    a completely different keystream.

4. Parallelism in Quarter-Rounds
--------------------------------
- Implemented parallelism using Python's ThreadPoolExecutor.
- use --parallel along with other arguments to parallelize.
- Used to compute the 4 quarter-rounds of a column/row in parallel but row after column in sequential.
- Results:
  * Time recorded for diffusion analysis: [0.0938720 seconds].
  * However, the parallel version was not faster in Python due to
    Global Interpreter Lock (GIL) and threading overhead.
- Observation:
  * Parallel quarter-rounds can help in C (true threads) but in Python,
    they are usually add overhead.
  * Understood the reason why cryptographic algorithms are usually
    implemented in C for performance.

5. Diffusion Discussion
-----------------------
- Salsa20 achieves diffusion by alternating column and row rounds.
- A small difference (1-bit change in counter or nonce) spreads across
  the 4x4 state matrix.
- After 2 double rounds, differences already affect most state words.
- By 20 rounds, the keystream is pseudorandom and completely uncorrelated
  with the input.

==================================================
