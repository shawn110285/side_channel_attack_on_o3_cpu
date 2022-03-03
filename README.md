# side_channel_attack_on_o3_cpu
POC code on side channel attack, including spectre attack and meltdown; these codes have been verified on the BOOMv3 (smallBoomconfig)

# Spectre Attack
Verified the following attack scenarios:
# (1) Bounds check bypass: 
    attack based on PHT (pattern History Table).
# (2) Branch target injection: 
    attack based on BTB (Branch Target Buffer).
# (3) Store Bypass: 
    attack based on memory disambiguation, the prediction on the Store & Load dependencies
# (4) Return Stack Buffer: 
   attack based on the Return Address Stack.
  
# Meltdown
   Illegal instruction exception and invalid address exception have been exploited. Experiments show illegal instruction exception can not break through the protection of the MMU, but the invalid address exception looks effective. 
   The illegal instruction is identified on the early stage (decoder) of the cpu pipeline and cpu will stop the further instruction fetching, however the invalid address exception is identified on the LSU unit, some more instructions have been fetched and executed speculatively.
