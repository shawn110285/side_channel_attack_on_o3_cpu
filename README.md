# side_channel_attack_on_o3_cpu
POC code on side channel attack, including spectre attack and meltdown; these codes have been verified on the BOOMv3 (smallBoomconfig)

# Spectre Attack
Verified the following attack scenarios:
## (1) Bounds check bypass: 
    attack based on PHT (pattern History Table).
## (2) Branch target injection: 
    attack based on BTB (Branch Target Buffer).
## (3) Store Bypass: 
    attack based on memory disambiguation, the prediction on the Store & Load dependencies
## (4) Return Stack Buffer: 
   attack based on the Return Address Stack.
  
# Meltdown
   Illegal instruction exception and invalid address exception have been exploited. Experiments show illegal instruction exception can not break through the protection of the MMU (because the illegal instruction will be identified on the early stage of the cpu pipeline), but the invalid address exception looks effective.   
