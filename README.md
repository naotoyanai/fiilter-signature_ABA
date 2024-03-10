# fiilter-signature_ABA
This repository is an implementation of our ISPEC paper: 
Yohei Watanabe, Naoto Yanai, Junji Shikata: IoT-REX: A Secure Remote-Control System for IoT Devices from Centralized Multi-designated Verifier Signatures. ISPEC 2023: 105-122. 
https://link.springer.com/chapter/10.1007/978-981-99-7032-2_7

### List of Files
1. `test.cpp`: scheme based on Vacuum filter (https://github.com/wuwuz/Vacuum-Filter). 
2. `trivial.cpp`: a trivial construction. 
3. `makefile`: file for the compilation 
4. `test_building.cpp`: a test program for the building environment. 



### List of Pre-installed libraries
1. Vacuum filter (https://github.com/wuwuz/Vacuum-Filter)
2. libsodium library (https://libsodium.gitbook.io/doc/)

### How to Compile
1. type ``git clone https://github.com/wuwuz/Vacuum-Filter``.
2. Relace ``test.cpp`` and ``makefile" in `Vacuumfilter` with the file in this repository. 
3. Put ``trivial.cpp`` in the same repository. 
4. type ``make all``
