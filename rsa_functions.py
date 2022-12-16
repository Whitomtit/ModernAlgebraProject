import random

import number_theory_functions


class RSA():
    def __init__(self, public_key, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def generate(digits=10):
        """
        Creates an RSA encryption system object

        Parameters
        ----------
        digits : The number of digits N should have

        Returns
        -------
        RSA: The RSA system containing:
        * The public key (N,e)
        * The private key (N,d)
        """

        # Choosing random p,q
        q = number_theory_functions.generate_prime(digits // 2 + 1)
        p = number_theory_functions.generate_prime(digits // 2 + 1)

        N = q * p
        K = (q - 1) * (p - 1)

        e = random.randrange(10 ** (digits - 1), 10 ** digits)
        
        while number_theory_functions.extended_gcd(e, K)[0] != 1:
            e = random.randrange(10 ** (digits - 1), 10 ** digits)

        # Calculating d
        d = number_theory_functions.modular_inverse(e, K)

        # Generating RSA system
        public_key = (N, e)
        private_key = (N, d)

        generated = RSA(public_key, private_key)
        return generated

    def encrypt(self, m):
        """
        Encrypts the plaintext m using the RSA system

        Parameters
        ----------
        m : The plaintext to encrypt

        Returns
        -------
        c : The encrypted ciphertext
        """
        return number_theory_functions.modular_exponent(m, self.public_key[1], self.public_key[0])

    def decrypt(self, c):
        """
        Decrypts the ciphertext c using the RSA system

        Parameters
        ----------
        c : The ciphertext to decrypt

        Returns
        -------
        m : The decrypted plaintext
       """
        decrypted_num = number_theory_functions.modular_exponent(c, self.private_key[1], self.private_key[0])

        return decrypted_num
