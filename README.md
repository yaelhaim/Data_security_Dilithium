Dilithium Digital Signature 
(Demo - This project was developed for academic purposes only and should not be used for real-world digital signature applications.)


Final Project – Data Security Course  
B.Sc. in Software Engineering  
Sami Shamoon College of Engineering (SCE)

Project Overview  
This project demonstrates a practical implementation of the CRYSTALS-Dilithium post-quantum digital signature algorithm, based on the NIST specification. The implementation is written in Python and includes attack simulations to evaluate the robustness of the signature scheme.

Objectives  
- Demonstrate the key generation process (public/private keys)  
- Generate digital signatures  
- Verify digital signatures  
- Simulate attacks by modifying messages, keys, and signatures  

Execution Stages  
1. Key Generation  
   Generates a public-private key pair and measures the execution time.

2. Message Signing  
   Signs a predefined message, displays the signature components (z, c, w), and records the signing time.

3. Signature Verification  
   Verifies the validity of the signature and reports performance metrics.

4. Attack Simulations  
   - Verifying with a tampered message  
   - Verifying with a wrong public key  
   - Modifying the witness (w)  
   - Modifying the challenge (c)  
   - Verifying a randomly generated (invalid) signature
     
5. How to Run  
  To run the demonstration script, use the following command:

    python examples/basic_usage.py

  Make sure that all required dependencies are installed (such as numpy):

    pip install numpy
    pip install --force-reinstall pycryptodome


