import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import numpy as np
import time
from dilithium.dilithium import OptimizedDilithium
from dilithium.rings import Polynomial  # Needed to access Polynomial.Q

# ANSI color codes
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
GREY = '\033[90m'
RESET = '\033[0m'

def main():
    print(f"{CYAN}=== DILITHIUM SIGNATURE METRICS ==={RESET}")
    print(f"{CYAN}Security Level: 2{RESET}")
    print(f"{CYAN}Message: 'Hello, Dilithium!'\n{RESET}")

    dilithium = OptimizedDilithium(security_level=2)
    message = b"Hello, Dilithium!"

    # -------------------- Key Generation --------------------
    print(f"{GREY}Generating keypair...{RESET}")
    start_ns = time.perf_counter_ns()
    pub, priv = dilithium.keygen()
    keygen_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    print(f"{GREEN}✓ Keys generated in {keygen_time_ms:.2f} ms{RESET}")
    print(f"{YELLOW}Public key (first 5 coefficients): {pub[1][0].coefficients[:5]}\n{RESET}")

    # -------------------- Signature Generation --------------------
    print(f"{GREY}Generating signature...{RESET}")
    start_ns = time.perf_counter_ns()
    try:
        z, c, w = dilithium.sign(message)
        sign_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        print(f"{GREEN}✓ Signature generated in {sign_time_ms:.2f} ms{RESET}")

        print(f"\n{CYAN}Signature Details:{RESET}")
        print(f"{GREY}-----------------{RESET}")
        print(f"{YELLOW}Challenge (c): {c.coefficients[:5]}{RESET}")
        print(f"{YELLOW}Response (z): {z[0].coefficients[:5]}{RESET}")
        print(f"{YELLOW}Witness (w): {w[0].coefficients[:5]}\n{RESET}")

        # -------------------- Signature Verification --------------------
        print(f"{GREY}Verifying signature...{RESET}")
        start_ns = time.perf_counter_ns()
        valid = dilithium.verify(message, (z, c, w), pub)
        verify_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        print(f"\n{CYAN}Performance Summary:{RESET}")
        print(f"{GREY}------------------{RESET}")
        print(f"{CYAN}Key Generation:{RESET} {keygen_time_ms:>8.2f} ms")
        print(f"{CYAN}Signing Time:  {RESET} {sign_time_ms:>8.2f} ms")
        print(f"{CYAN}Verify Time:   {RESET} {verify_time_ms:>8.2f} ms")
        print(f"{CYAN}Total Time:    {RESET} {(keygen_time_ms + sign_time_ms + verify_time_ms):>8.2f} ms")

        if valid:
            print(f"\n{GREEN}✓ Signature verification successful{RESET}")
        else:
            print(f"\n{RED}✗ Signature verification failed{RESET}")

        # -------------------- Test 1: Tampered message --------------------
        print(f"\n{GREY}Verifying with a **tampered message** (should fail)...{RESET}")
        tampered_message = b"Hacked message!"
        tampered_valid = dilithium.verify(tampered_message, (z, c, w), pub)
        if tampered_valid:
            print(f"{RED}✗ Verification passed for tampered message – ERROR{RESET}")
        else:
            print(f"{GREEN}✓ Verification correctly failed for tampered message{RESET}")

        # -------------------- Test 2: Wrong public key --------------------
        print(f"\n{GREY}Verifying with a **wrong public key** (should fail)...{RESET}")
        wrong_pub, _ = dilithium.keygen()
        wrong_key_valid = dilithium.verify(message, (z, c, w), wrong_pub)
        if wrong_key_valid:
            print(f"{RED}✗ Verification passed with wrong public key – ERROR{RESET}")
        else:
            print(f"{GREEN}✓ Verification correctly failed with wrong public key{RESET}")

        # -------------------- Test 3: Modified signature --------------------
        
        print(f"\n{GREY}Verifying with a **modified witness (w)** (should fail)...{RESET}")
        w_tampered = [
            Polynomial([c + 123 for c in poly.coefficients])
            for poly in w
        ]
        valid = dilithium.verify(message, (z, c, w_tampered), pub)
        if valid:
            print(f"{RED}✗ Verification passed with modified witness – ERROR{RESET}")
        else:
            print(f"{GREEN}✓ Verification correctly failed with modified witness{RESET}")

         # -------------------- Test 4: Modified signature --------------------
        print(f"\n{GREY}Verifying with a **modified challenge (c)** (should fail)...{RESET}")
        c_tampered = Polynomial([(coeff + 1) % Polynomial.Q for coeff in c.coefficients])
        valid = dilithium.verify(message, (z, c_tampered, w), pub)
        if valid:
            print(f"{RED}✗ Verification passed with modified challenge – ERROR{RESET}")
        else:
            print(f"{GREEN}✓ Verification correctly failed with modified challenge{RESET}")

         # --------------------- Test 5: Modified signature ---------------------
        print(f"\n{GREY}Verifying with a **completely random signature** (should fail)...{RESET}")
        z_fake = [Polynomial(np.random.randint(0, Polynomial.Q, size=256).tolist()) for _ in z]
        c_fake = Polynomial(np.random.randint(0, Polynomial.Q, size=len(c.coefficients)).tolist())
        w_fake = [Polynomial(np.random.randint(0, Polynomial.Q, size=256).tolist()) for _ in w]

        valid = dilithium.verify(message, (z_fake, c_fake, w_fake), pub)
        if valid:
            print(f"{RED}✗ Verification passed with random signature – ERROR{RESET}")
        else:
            print(f"{GREEN}✓ Verification correctly failed with random signature{RESET}")

    except Exception as e:
        print(f"\n{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()
