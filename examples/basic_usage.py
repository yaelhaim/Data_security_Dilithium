import time
from dilithium.dilithium import OptimizedDilithium
from dilithium.rings import Polynomial  # Needed to access Polynomial.Q

def main():
    print("=== DILITHIUM SIGNATURE METRICS ===")
    print("Security Level: 2")
    print("Message: 'Hello, Dilithium!'\n")

    # Initialize the Dilithium signature scheme with security level 2
    dilithium = OptimizedDilithium(security_level=2)
    message = b"Hello, Dilithium!"

    # -------------------- Key Generation --------------------
    print("Generating keypair...")
    start_ns = time.perf_counter_ns()
    pub, priv = dilithium.keygen()
    keygen_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
    print(f"✓ Keys generated in {keygen_time_ms:.2f} ms")
    print(f"Public key (first 5 coefficients): {pub[1][0].coefficients[:5]}\n")

    # -------------------- Signature Generation --------------------
    print("Generating signature...")
    start_ns = time.perf_counter_ns()
    try:
        z, c, w = dilithium.sign(message)
        sign_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000
        print(f"✓ Signature generated in {sign_time_ms:.2f} ms")

        # Display parts of the signature
        print("\nSignature Details:")
        print("-----------------")
        print(f"Challenge (c): {c.coefficients[:5]}")
        print(f"Response (z): {z[0].coefficients[:5]}")
        print(f"Witness (w): {w[0].coefficients[:5]}\n")

        # -------------------- Signature Verification --------------------
        print("Verifying signature...")
        start_ns = time.perf_counter_ns()
        valid = dilithium.verify(message, (z, c, w), pub)
        verify_time_ms = (time.perf_counter_ns() - start_ns) / 1_000_000

        # Performance summary
        print("\nPerformance Summary:")
        print("------------------")
        print(f"Key Generation: {keygen_time_ms:>8.2f} ms")
        print(f"Signing Time:   {sign_time_ms:>8.2f} ms")
        print(f"Verify Time:    {verify_time_ms:>8.2f} ms")
        print(f"Total Time:     {(keygen_time_ms + sign_time_ms + verify_time_ms):>8.2f} ms")

        if valid:
            print("\n✓ Signature verification successful")
        else:
            print("\n✗ Signature verification failed")

        # -------------------- Test 1: Tampered message --------------------
        print("\nVerifying with a **tampered message** (should fail)...")
        tampered_message = b"Hacked message!"
        tampered_valid = dilithium.verify(tampered_message, (z, c, w), pub)
        if tampered_valid:
            print("✗ Verification passed for tampered message – ERROR")
        else:
            print("✓ Verification correctly failed for tampered message")

        # -------------------- Test 2: Wrong public key --------------------
        print("\nVerifying with a **wrong public key** (should fail)...")
        wrong_pub, _ = dilithium.keygen()
        wrong_key_valid = dilithium.verify(message, (z, c, w), wrong_pub)
        if wrong_key_valid:
            print("✗ Verification passed with wrong public key – ERROR")
        else:
            print("✓ Verification correctly failed with wrong public key")

        # -------------------- Test 3: Modified signature --------------------
        # Verifying with a **modified signature (z)** (should fail)...
        print("\nVerifying with a **modified signature (z)** (should fail)...")

        # Tamper with z coefficients significantly to break bounds
        z_tampered = [Polynomial((poly.coefficients + 1_000_000) % Polynomial.Q) for poly in z]
        valid = dilithium.verify(message, (z_tampered, c, w), pub)

        if valid:
            print("✗ Verification passed with modified signature – ERROR")
        else:
            print("✓ Verification correctly failed with modified signature")


    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
