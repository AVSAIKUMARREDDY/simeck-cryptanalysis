#!/usr/bin/env python
# coding: utf-8

# In[8]:


######### Simeck Cipher 32/64 upto rth round ########
# define call the function with key and number of rounds
# aslo you can define the rounds in encyption and decryprtion
#uncomment below command to install the pylfs dependency
#!pip install pylfsr
from pylfsr import LFSR
import math
class SimeckCipher:
    def __init__(self,rounds,masterkey):
        self.blocksize = 32
        self.keysize = 64
        self.wordsize = self.blocksize // 2
        self.numrounds = rounds
        self.poly = self.get_poly(self.numrounds)
        self.mod = 1<<self.wordsize
        self.roundkeys=self.roundkeygen(masterkey)
    
    def leftrotate(self,n,d):
        return ((n << d) % self.mod) | (n >> (self.wordsize - d))
    
    def roundfun(self,kr,left,right):
        temp = left
        left = right ^ (left & self.leftrotate(left, 1)) ^ self.leftrotate(left, 1) ^ kr
        right = temp
        return left, right
    
    def roundkeygen(self, masterkey):
        states = []
        for i in range(self.keysize // self.wordsize):
            states.append(masterkey % self.mod)
            masterkey >>= self.wordsize
        #print(states)
        constant = self.mod - 4
        round_keys = []
        for i in range(self.numrounds):
            round_keys.append(states[0])
            left, right = states[1], states[0]
            left, right = self.roundfun(constant ^ self.poly[i], left, right)
            states.append(left)
            states.pop(0)
            states[0] = right
        return tuple(round_keys)
    
    def get_poly(self,numrounds):
        state = [1,1,1,1,1]
        fpoly = [5,2]
        L = LFSR(initstate=state,fpoly=fpoly)
        seq = L.runKCycle(self.numrounds)
        return seq
    
    def encryption(self,pt,r):
        left = pt >> self.wordsize
        right = pt % self.mod

        #print('left',left)
        #print('right',right)
        for i in range(r):
            left, right = self.roundfun(self.roundkeys[i], left, right)
            #print(' enc left', hex(left))
            #print('enc right', hex(right))
        ciphertext = (left << self.wordsize) | right
        #print('ciphertext', ciphertext)
        #print('roundkeys', self.roundkeys)
        #print('poly', self.poly)
        return ciphertext
        
    def decryption(self,ct,r):
        left = ct >> self.wordsize
        right = ct % self.mod
        #print('left',left)
        #print('right',right)
        #print(r)
        for i in reversed(range(self.numrounds)):
            #print(i)
            if((i+1)==(self.numrounds-r)):
                break
            right,left = self.roundfun(self.roundkeys[i], right,left)
            #print(r)
            #print('dec left', hex(left))
            #print('dec right',  hex(right))
        pt =(left << self.wordsize) | right
        #print('plaintext', pt)
        #print('roundkeys', self.roundkeys)
        #print('poly', self.poly)
        return pt
    
    def decryption_last(self,ct,r,key):
        left = ct >> self.wordsize
        right = ct % self.mod
        #print('left',left)
        #print('right',right)
        #print(r)
        right,left = self.roundfun(key, right,left)
            #print(r)
            #print('dec left', hex(left))
            #print('dec right',  hex(right))
        pt =(left << self.wordsize) | right
        #print('plaintext', pt)
        #print('roundkeys', self.roundkeys)
        #print('poly', self.poly)
        return pt    

    
def main():
    pt = 0x23456789
    #pt2= 0x59877898
    key= 0x8888777799990000
# call the function with number of rounds and key
    sc = SimeckCipher(6,key)
    ciphertext = sc.encryption(pt,6)
    print("plaintext before encyption :",hex(pt))
    #ciphertext2 = sc.encryption(pt2,6)
    #ciphertext5 = sc.encryption(pt,5)
    text = sc.decryption(ciphertext,6)
    #print(hex(ciphertext5))
    print("ciphertext :",hex(ciphertext))
    #print(hex(ciphertext2))
    print("plaintext after decryption :",hex(text))
    #print(pt^pt2)
    #print((ciphertext^ciphertext2))
    #print(sc.roundkeys)

#if __name__ == "__main__":
 #   main()

