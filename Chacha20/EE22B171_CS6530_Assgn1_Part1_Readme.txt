==================================================
Part 1: ChaCha20: Diffusion Analysis
==================================================

==================================================
README: ChaCha20 Diffusion Analysis
==================================================

This file documents the analysis and experimentation performed on the ChaCha20 stream cipher.  
It covers the following aspects:

1. How to Run
   - Instructions to run the Python3 implementation of ChaCha20.
   - Commands include generating keystream, encrypting/decrypting files,
     performing differential analysis, and using parallel execution.

2. Differential Analysis
   - Compares the internal states of ChaCha20 for different counter values.
   - Shows how a small change in the counter propagates through the 4x4 state matrix.
   - Confirms the Avalanche Effect and illustrates how diffusion spreads over multiple double rounds.

3. Parallelism in Quarter-Rounds
   - Demonstrates use of Python's ThreadPoolExecutor to parallelize quarter-round computations.
   - Provides timing observations and discussion about Python threading overhead.

4. Diffusion Discussion
   - Analysis of how differences propagate in ChaCha20 rounds.
   - Observations about full diffusion, pseudorandomness, and keystream independence.

5. Comparison with Salsa20
   - Highlights differences in diffusion speed, mixing strength, and security implications.
   - Explains why ChaCha20 achieves faster and stronger diffusion than Salsa20.

Notes:
- All analysis uses default key, nonce, and counter (all zeros) unless specified.
- Differential analysis is performed between selected counter values to study diffusion behavior.
- Execution times are recorded to provide performance insights.
- The total file size of EE22B171_CS6530_Assgn1_Part1.txt is 68 KB.


1. How to Run
-------------
The code is written in Python3. To run the ChaCha20 implementation:

    python EE22B171_ChaCha20.py --keystream
    python EE22B171_ChaCha20.py --enc --in input.txt --out encrypted.bin
    python EE22B171_ChaCha20.py --dec --in encrypted.bin --out output.bin
    python EE22B171_ChaCha20.py --diff 0 1
    python EE22B171_ChaCha20.py --diff 71 72
    python EE22B171_ChaCha20.py --keystream --parallel
    python EE22B171_ChaCha20.py --keystream --log dr [log file will be created that contains all the double round].

Notes:
- By default, the key, nonce, and counter are set to all zeros.
- The --diff option generates a differential analysis file that shows
  how the state changes round by round.
- The quarter round can be dumped in the log file by using --log dr+qr.

2. Differential Analysis: Counter 0 vs Counter 1
------------------------------------------------
- Input: Key = 32-byte all zeros, Nonce = 12-byte all zeros (ChaCha uses 96-bit nonce).
- Command: python EE22B171_ChaCha20.py --diff 0 1
- This command will take 0 and 1 as counter and perform the differential analysis.
- Comparison of states between counter = 0 and counter = 1.

Initial State
61707865 3320646e 79622d32 6b206574   61707865 3320646e 79622d32 6b206574   00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000   00000001 00000000 00000000 00000000   00000001 00000000 00000000 00000000
After DR1
e45fd249 1bb820a6 e31a88ea e667a9fe   d35fd249 1be820a9 d31f88da 8e7f397f   37000000 0050000f 30050030 68189081
2a3bf673 86bf4098 460b500a fa169886   c1bf4b8a feb74a18 a1f753eb f91e808c   eb84bdf9 78080a80 e7fc03e1 0308180a
538dca0e 0c439641 00fa16bc 8a08812a   578cda2e 042c17b1 010a06a9 49f7792a   04011020 086f81f0 01f01015 c3fff800
6bbf8b09 c33013d6 bb9f9849 87c62165   2bbe8409 c63023e6 ab8f9939 87d62152   40010f00 05003030 10100170 00100037
After DR2
b20e0da6 21219e43 79c69196 8eb9d107   bc389fa8 b9ba7055 3085e7bd 009ee8cf   0e36920e 989bee16 4943762b 8e2739c8
28bfa54e 0e8a389f 7919a4b4 323f2639   0ab5eecd 3111471a 86b484ee 7f517f6d   220a4b83 3f9b7f85 ffad205a 4d6e5954
69727d19 12e796ec d1875d88 602bb1ec   47323b48 1289b2d8 f81f7778 ad21d4ee   2e404651 006e2434 29982af0 cd0a6502
601c8a8d 18cf3767 60d10ebc 17aa36ca   6fb0164a add42d2e 81ed68a2 66145871   0fac9cc7 b51b1a49 e13c661e 71be6ebb
After DR3
0287a2a1 d2dc39ef f2ecf51e c3876afe   05ef5f24 0a23c120 f0ab6935 e071f61f   0768fd85 d8fff8cf 02479c2b 23f69ce1
9276b821 37ccb7a7 1fe6c459 e5f95617   e2a62d59 57de135b 25e917b1 97526658   70d09578 6012a4fc 3a0fd3e8 72ab304f
d7b18523 a0952ff2 131f6ff5 6f38a9cc   cf306ca2 5dc44a81 e020206c c89e2f10   1881e981 fd516573 f33f4f99 a7a686dc
5c427a5f 1d928d7b f4d2b4da 1a640884   5d348f46 50e06f03 48e9dd8c 7cb1007c   0176f519 4d72e278 bc3b6956 66d508f8
After DR4
ce7e87d9 a31ffb1b 6f562e4d 3684a3ab   ac8a366d 1ea1417c f378dd8d 42858c8d   62f4b1b4 bdbeba67 9c2ef3c0 74012f26
c30e842c 3b7f9ace 88e11b18 1e1a71ef   1258fdc0 aaa2f959 8f0ff2dc 6ba266d5   d15679ec 91dd6397 07eee9c4 75b8173a
72e14c98 416f21b9 6753449f 19566d45   38ec3250 98dac5bb 566f0cee 652a878b   4a0d7ec8 d9b5e402 313c4871 7c7ceace
a3424a31 01b086da b8fd7b38 42fe0c0e   25bf8a9f bb21eb1d d8e5564b aa681e82   86fdc0ae ba916dc7 60182d73 e896128c


- Observations:

At the Initial State, the only difference between counter=0 and counter=1
appears in the counter word of the state matrix (one 32-bit word changed).

After Double Round 1:
- The differences is reached to almost every row and column but still some bits are not affected.
- This shows that ChaCha20, starts to diffuse faster than salsa20.

After Double Round 2:
- More state words start to differ, and the differences propagate both column-wise and diagonally.
- Differences are present in most rows, though some regularities still remain.

After Double Round 3:
- Differences are spread across nearly the entire 4x4 state.
- Nonlinear operations dominate and the state words look highly uncorrelated.

After Double Round 4:
- Complete diffusion is achieved. Almost all state words diverge
  significantly, and the outputs are fully uncorrelated.
- From this point onward, the keystreams of counter=0 and counter=1
  are entirely distinct and pseudorandom.

Summary:
- Confirms Avalanche Effect.
- Diffusion begins gradually in ChaCha20 but becomes strong after a few double rounds.
- By the 3rd and 4th double rounds, the state is fully mixed and the effect of
  the changed counter spreads everywhere.
- This confirms that ChaCha20 requires multiple rounds for strong diffusion,
  but once reached, the keystream blocks are fully distinct.

- Execution time recorded: [0.0052850 seconds].


3. Differential Analysis: Counter 71 vs Counter 72
--------------------------------------------------
- Same key and nonce as above.
- My roll number: EE22B171, hence the counter values are initialised 71 and 72.
- Command: python EE22B171_ChaCha20.py --diff 71 72
- Initial states differ only in the counter value.

Initial State
61707865 3320646e 79622d32 6b206574   61707865 3320646e 79622d32 6b206574   00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000   00000000 00000000 00000000 00000000
00000047 00000000 00000000 00000000   00000048 00000000 00000000 00000000   0000000f 00000000 00000000 00000000
After DR1
115fd245 00481de7 b2dd8cb6 80635b3d   bc5fd245 00381e0e 62a28d63 e7217ccc   ad000000 007003e9 d07f01d5 674227f1
f5ae2d47 ecad6d39 8536fa2a b9f5723c   d4edc838 c4e554ba 4b62e68b ad53db86   2143e57f 28483983 ce541ca1 14a6a9ba
574f01ef ad7a248f fd2e32e7 d61ef93f   d35b4c0f 7766a997 fc7ea294 9592513f   84144de0 da1c8d18 01509073 438ca800
abc5ca1e 04344f87 86ccc505 83f62d90   6bc9231e 7b359a57 6956b78a 83462d3d   c00ce900 7f01d5d0 ef9a728f 00b000ad
After DR2
9e24df26 36c46d34 4adc6496 80f8b4bc   e177752f 0bcde2a0 e47b29d9 3cdcc172   7f53aa09 3d098f94 aea74d4f bc2475ce
4b50b9f9 f714a161 5ddd14d0 823b4fcd   01d672b7 1370a356 0a1d4656 eee5e47f   4a86cb4e e4640237 57c05286 6cdeabb2
985d8dba e3dc6af9 69de21ab cfd45e39   a7768b85 5568383e 2e1985eb d2a0d666   3f2b063f b6b452c7 47c7a440 1d74885f
2a75cb57 8b78d9ea 01f34c93 efa0b58e   78341278 e7706533 4958f8e5 3ff1a275   5241d92f 6c08bcd9 48abb476 d05117fb
After DR3
a2109718 9c2867c8 f63f2a7d 666f0a67   c5043a76 e04134c6 dee4f91a 7ab9a776   6714ad6e 7c69530e 28dbd367 1cd6ad11
46d146e3 a2195d21 700fea43 97eacf87   0f0cde2d 7a2d09dd ff4efea4 c692d4a4   49dd98ce d83454fc 8f4114e7 51781b23
1a43d1a2 a71d3a83 20636e54 8f39d82a   c833c4a4 524d13d7 f053f252 56124d71   d2701506 f5502954 d0309c06 d92b955b
e8b4963d 105dcb28 9560c5d8 f82a19bb   96f8884f 011decc3 bf47fcd9 0a753759   7e4c1e72 114027eb 2a273901 f25f2ee2
After DR4
692b9358 aad051f8 20f9a956 361b63f4   ee43b11e 72b011d2 45d1a1fd 1db6882a   87682246 d860402a 652808ab 2badebde
8f3b6ad0 771ac27c ef6d5286 2737c985   625fffdd 9396a937 7d8ff4d8 024513fd   ed64950d e48c6b4b 92e2a65e 2572da78
f886908b 69e74b12 20f0df24 1cd71200   d6f49604 cee908a1 bda8a5fe 90991e47   2e72068f a70e43b3 9d587ada 8c4e0c47
ba5d1e7e 79dbeea3 781d39e8 6c3cd5c6   a504c08e b90ef338 484cdbb4 cce48369   1f59def0 c0d51d9b 3051e25c a0d856af

- Diffusion seems to happen faster, diffusion is almost reached by 2 round itself.
- After the first double round itself, the diff seems less recognizable.
- After the 4th double round, the difference spreads to all state words,
  achieving complete diffusion.
- Execution time: [0.0058283 seconds].
- Observations:
  * Confirms avalanche effect.
  * Each block of ChaCha20 is independent; changing the counter produces
    a completely different keystream.


4. Parallelism in Quarter-Rounds
--------------------------------
- Implemented parallelism using Python's ThreadPoolExecutor.
- Use --parallel along with other arguments to parallelize.
- Computed the 4 quarter-rounds of a column/diagonal in parallel, but
  column first and then diagonal.
- Results:
  * Time recorded for diffusion analysis: [0.0860928 seconds].
  * Just like Salsa20,here also the parallel version was not faster in Python due to
    Global Interpreter Lock (GIL) and threading overhead.
- Observation:
  * Parallel quarter-rounds would help in C (true threads), but in Python,
    they usually add overhead.
  * Confirms why cryptographic algorithms are usually implemented in C
    for performance.


5. Diffusion Discussion
-----------------------
- ChaCha20 achieves diffusion by alternating column rounds and diagonal rounds.
- A small difference (1-bit change in counter or nonce) spreads across
  the 4x4 state matrix.
- After 2 double rounds, differences already affect most state words.
- By 20 rounds, the keystream is pseudorandom and completely uncorrelated
  with the input.

6. Comparison of Diffusion: Salsa20 vs ChaCha20
--------------------------------------------
1. Diffusion Speed
   - Salsa20: Diffusion builds up more gradually. It takes several double rounds
     (around 4 or more) before changes in one word spread fully across the state.
   - ChaCha20: Diffusion is faster. Due to the modified quarter-round (rotating
     across diagonals and columns differently), by the 3rd or 4th double round,
     the entire state is strongly mixed.

2. Mixing Strength
   - Salsa20: Quarter-round operations provide good mixing, but the effect of a
     single bit change propagates slightly slower across the 16-word state.
   - ChaCha20: Stronger per-round mixing. The extra XOR and rotation pattern
     accelerates how differences spread, leading to earlier avalanche behavior.

3. Security Implications
   - Salsa20: Requires more rounds to achieve comparable diffusion strength.
   - ChaCha20: Achieves stronger diffusion earlier, which is one reason ChaCha20
     is considered more secure at reduced-round versions compared to Salsa20.
   - Timing is almost similar for both , sometimes salsa being faster.

Summary:
Both Salsa20 and ChaCha20 achieve full diffusion after enough rounds, but ChaCha20
spreads differences faster and more uniformly across the state. This makes ChaCha20
more resistant to certain forms of cryptanalysis at lower round counts.

==================================================
