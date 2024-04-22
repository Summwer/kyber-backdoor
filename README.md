
# Guidance for Kyber-backdoor


Before compile our experiment, please download the depending library XKCP first:
```
cd
apt-get install xsltproc
git clone https://github.com/XKCP/XKCP.git
cd XKCP
git submodule update --init
time make AVX2/libXKCP.a
time make AVX2/libXKCP.so

mkdir -p $HOME/include
mkdir -p $HOME/lib
ln -s $HOME/XKCP/bin/AVX2/libXKCP.a.headers $HOME/include/libkeccak.a.headers
ln -s $HOME/XKCP/bin/AVX2/libXKCP.a $HOME/lib/libkeccak.a
ln -s $HOME/XKCP/bin/AVX2/libXKCP.so $HOME/lib/libkeccak.so
```

Then, one could test the our kyber-backdoor implementation through the following command:
```
#First compile mceliece348864
cd mceliece348864
./build
cd ..

cd kyber-backdoor/ref
export CPATH="$CPATH:$HOME/include"
export LIBRARY_PATH="$LIBRARY_PATH:$HOME/lib"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/lib:./"
./build
./test_kyber_backdoor768 0> backdoor_attack768.rsp
./test_kyber_backdoor1024 0> backdoor_attack1024.rsp
```

Beides, it will also output the number of elements in ct which rearch the border case. We can get the Figure 2 in of the article "
Post-Quantum Backdoor for Kyber-KEM".


One could reproduce the cost test stated in section 4 of the article "
Post-Quantum Backdoor for Kyber-KEM" by the following command: 

```
cd kyber-backdoor/avx2
export CPATH="$CPATH:$HOME/include"
export LIBRARY_PATH="$LIBRARY_PATH:$HOME/lib"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$HOME/lib"
make #ignore the error, just used to generate KeccakP-1600-times4-SIMD256.o
./build
./test_backdoor_speed768
./test_backdoor_speed1024
./test_speed768
./test_speed1024
```
