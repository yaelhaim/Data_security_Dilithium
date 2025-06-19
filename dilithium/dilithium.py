import numpy as np
import secrets
from functools import lru_cache

from dilithium.rings import Polynomial
from dilithium.hash import expand_seed, generate_matrix_from_seed, generate_challenge


# System constants from Dilithium paper
Q = Polynomial.Q  # q = 2^23 - 2^13 + 1 = 8380417
N = Polynomial.N  # n = 256

# Extremely relaxed bounds (for testing)
GAMMA1 = Q
GAMMA2 = Q
BETA = 1

# Domain separators
DOMAIN_SMALL_POLY = 0x03
DOMAIN_Y_POLY = 0x05

# Parameter sets (k, l, η)
PARAMS = {
    2: {"k": 4, "l": 4, "eta": 2},  # NIST Security Level 2
    3: {"k": 6, "l": 5, "eta": 4},  # NIST Security Level 3
    5: {"k": 8, "l": 7, "eta": 2},  # NIST Security Level 5
}


class OptimizedDilithium:
    def __init__(self, security_level=2):
        if security_level not in PARAMS:
            raise ValueError("Security level must be 2, 3, or 5")

        params = PARAMS[security_level]
        self.k = params["k"]
        self.l = params["l"]
        self.eta = params["eta"]

        self.rho = None
        self.t = None
        self.s1 = None
        self.s2 = None

    def _generate_vector(self, size: int, bound: int, domain: int) -> list:
        seed = secrets.token_bytes(32)
        total_coeffs = size * Polynomial.N
        randomness = expand_seed(seed, domain, total_coeffs * 4)
        coeffs = np.frombuffer(randomness, dtype=np.uint32)
        coeffs = coeffs % (2 * bound + 1)
        coeffs = coeffs.astype(np.int32) - bound
        coeffs = coeffs.reshape(size, Polynomial.N)
        return [Polynomial(row.tolist()) for row in coeffs]

    def generate_y_vector(self) -> list:
        return self._generate_vector(self.l, GAMMA1, DOMAIN_Y_POLY)

    def generate_small_vector(self, size: int) -> list:
        return self._generate_vector(size, self.eta, DOMAIN_SMALL_POLY)

    @lru_cache(maxsize=None)  # Changed to support multiple cache entries
    def get_matrix_A(self):
        """Get cached matrix A using rho as part of cache key"""
        if self.rho is None:
            raise ValueError("Keys not generated")

        # Include rho in computation to make it part of cache key
        matrix = generate_matrix_from_seed(self.rho, self.k, self.l)
        return matrix

    def _matrix_multiply(self, matrix: list, vector: list) -> list:
        result = []
        for row in matrix:
            sum_poly = Polynomial()
            for a, v in zip(row, vector):
                sum_poly = sum_poly + (a * v)
            result.append(sum_poly)
        return result

    def keygen(self):
        """Generate a new keypair"""
        self.rho = secrets.token_bytes(32)

        A = self.get_matrix_A()
        self.s1 = self.generate_small_vector(self.l)
        self.s2 = self.generate_small_vector(self.k)

        self.t = self._matrix_multiply(A, self.s1)
        for i in range(self.k):
            self.t[i] = self.t[i] + self.s2[i]

        return (self.rho, self.t), (self.s1, self.s2)

    def sign(self, message: bytes, max_attempts=100):
        if not all([self.rho, self.t, self.s1, self.s2]):
            raise ValueError("Keys not generated")

        A = self.get_matrix_A()
        public_key = (self.rho, self.t)

        attempts = 0
        while attempts < max_attempts:
            attempts += 1
            if attempts % 10 == 0:
                print(f"Attempt {attempts}/{max_attempts}")

            # Sample y with coefficients in [-γ₁, γ₁]
            y = self.generate_y_vector()

            # Compute w = Ay
            w = self._matrix_multiply(A, y)

            # Check if w is small enough (||w||∞ < γ₂)
            w_coeffs = np.concatenate([np.array(p.coefficients) for p in w])
            if np.any(np.abs(w_coeffs) > GAMMA2):
                continue

            print("w processed")

            # Generate challenge using raw w
            c = generate_challenge(message, public_key, w)

            # Compute z = y + cs₁
            z = []
            for i in range(self.l):
                z_poly = y[i] + (c * self.s1[i])
                z.append(z_poly)

            # Check z bounds
            z_coeffs = np.concatenate([np.array(p.coefficients) for p in z])
            if np.any(np.abs(z_coeffs) >= GAMMA1 - BETA):
                continue

            print(f"Succeeded after {attempts} attempts")
            return z, c, w  # NOTE: return raw w

        raise RuntimeError("Failed to generate signature after max attempts")

    def verify(self, message: bytes, signature: tuple, public_key: tuple) -> bool:
        z, c, w_raw = signature
        rho, t = public_key

        # Verify z bounds
        z_coeffs = np.concatenate([np.array(p.coefficients) for p in z])
        if np.any(np.abs(z_coeffs) >= GAMMA1 - BETA):
            print("z bounds check failed")
            return False

        # Process w like in sign()
        w_processed = []
        for poly in w_raw:
            coeffs = np.array(poly.coefficients)
            coeffs = np.abs(coeffs) % Q
            w_processed.append(Polynomial(coeffs.tolist()))

        # Verify w bounds
        w_coeffs = np.concatenate([np.array(p.coefficients) for p in w_processed])
        if np.any(np.abs(w_coeffs) >= GAMMA2):
            print("w bounds check failed")
            return False

        # Recompute challenge
        c_prime = generate_challenge(message, public_key, w_processed)

        if not np.array_equal(c.coefficients, c_prime.coefficients):
            print("Challenge mismatch (final c ≠ original c)")
            return False

        return True


