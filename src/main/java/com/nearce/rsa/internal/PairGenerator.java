/*
 * Copyright (c) 2015 Wyatt Childers.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.nearce.rsa.internal;

import java.math.BigInteger;
import java.util.Random;

import static java.math.BigInteger.*;

public class PairGenerator {
    private static final Random internalRand = new Random(System.currentTimeMillis());
    private final int testQ;

    /**
     * Constructs a PairGenerator object, which will always test all prime numbers
     * with Fermat's little theorem the specified amount of times, unless otherwise specified.
     *
     * @param testQ the number of times a generated number must pass Fermat's little theorem
     *              to be considered prime, must be at least 1
     */
    public PairGenerator(int testQ) {
        if (testQ < 1) {
            throw new IllegalArgumentException("The number of times to test the integer must be at least 1.");
        }
        this.testQ = testQ;
    }

    /**
     * Generates an RSA {@link com.nearce.rsa.internal.KeyPair} based on two prime numbers
     * of specified digit count.
     *
     * @param pDigits the number of digits for the {@link java.math.BigInteger} p, must be at least 1
     * @param qDigits the number of digits for the {@link java.math.BigInteger} q, must be at least 1
     * @return The generated {@link com.nearce.rsa.internal.KeyPair}
     */
    public KeyPair keyGen(int pDigits, int qDigits) {
        BigInteger p = getPrime(pDigits, testQ);
        BigInteger q = getPrime(qDigits, testQ);

        BigInteger n = p.multiply(q);
        BigInteger t = p.subtract(ONE).multiply(q.subtract(ONE));

        BigInteger[] res = findED(t);

        return new KeyPair(new PublicKey(n, res[0]), new PrivateKey(n, res[1])); // res[0] = e, and res[1] = d
    }

    /**
     * Creates a random {@link java.math.BigInteger} greater between 1, and a provided maximum value.
     *
     * @param max the maximum value for the integer
     * @return the generated {@link java.math.BigInteger}
     */
    public BigInteger genBoundInteger(BigInteger max) {
        return genBoundInteger(ONE, max);
    }

    /**
     * Creates a random {@link java.math.BigInteger} greater between a provided minimum, and maximum value.
     *
     * @param min the minimum value for the integer, must be less than {@code max}
     * @param max the maximum value for the integer, must be greater than {@code min}
     * @return the generated {@link java.math.BigInteger}
     */
    public BigInteger genBoundInteger(BigInteger min, BigInteger max) {
        if (min.compareTo(max) == 1) {
            throw new IllegalArgumentException("The maximum value must be greater than the minimum value.");
        }
        BigInteger res;
        do {
            // Generate an integer based on a random bit length, and random bit values
            res = new BigInteger((int) (max.bitLength() * internalRand.nextDouble()), internalRand);
        } while (res.compareTo(min) != 1 && res.compareTo(max) != -1); // Ensure the integer is within bounds
        return res;
    }

    /**
     * Takes some integer a, and finds a number e, and d such that
     * ad + ey = gcd(a, e) is satisfied.
     *
     * @param a the upper bounding integer for the extended euclidean algorithm
     * @return variables e, and d in an array with length 2 in their respective positions
     */
    public BigInteger[] findED(BigInteger a) {
        BigInteger e;
        BigInteger d;
        do {
            e = genBoundInteger(a); // Generate an integer e, between 1, and a
            d = findD(a, e);
        } while (d == null);
        return new BigInteger[] {e, d};
    }

    /**
     * Takes some integer a, and some integer e, then finds the multiplicative
     * inverse of e.
     *
     * @param a (p-1)(q-1)
     * @param e An integer bound by 1 <= e <= a
     * @return the multiplicative inverse of e, or null if it couldn't be found
     */
    public BigInteger findD(BigInteger a, BigInteger e) {
        // Execute the euclidean algorithm
        BigInteger[] res = extendedEuclidean(a, e);
        // Check for a remainder of 1, and that a isn't divisible by e, then
        // return either null (d can't be found), or return the result of y % a, giving you d
        return !res[0].equals(ONE) || a.mod(e).equals(ZERO) ? null : res[2].mod(a);
    }

    /**
     * Implements the extended euclidean algorithm. Taking some integer a, and b,
     * such that ax + by = gcd(a, b) is satisfied.
     *
     * @param a the larger number
     * @param b the smaller number
     * @return the gcd, x, and y in an array with length 3 in their respective positions
     */
    public BigInteger[] extendedEuclidean(BigInteger a, BigInteger b) {
        if (b.equals(ZERO)) {
            return new BigInteger[] {a, ONE, ZERO};
        }
        BigInteger[] res = extendedEuclidean(b, a.mod(b));
        return new BigInteger[] {
                res[0],
                res[2],
                res[1].subtract(a.divide(b).multiply(res[2]))
        };
    }

    /**
     * Generate a prime number {@code digits} long, which must pass Fermat's little
     * theorem {@code testQ} times.
     *
     * @param digits the number of digits long the number should be, must be at least 1
     * @param testQ the number of times the test should be performed, must be at least 1
     * @return the resulting prime {@link java.math.BigInteger}
     */
    public BigInteger getPrime(int digits, int testQ) {
        BigInteger b;
        do {
            // Constructs a big integer from a string "digits" long
            b = new BigInteger(numString(digits));
        } while (!isPrime(b, testQ)); // Repeat if the test fails
        return b;
    }

    /**
     * Test to see if the provided {@link java.math.BigInteger} is prime using Fermat's little theorem.
     *
     * @param integer the {@link java.math.BigInteger} to test
     * @param testQ the number of times the test should be performed, must be at least 1
     * @return false, if the integer failed the test
     */
    public boolean isPrime(BigInteger integer, int testQ) {
        if (testQ < 1) {
            throw new IllegalArgumentException("The number of times to test the integer must be at least 1.");
        }

        // Test the integer testQ times
        for (int i = 0; i < testQ; ++i) {
            BigInteger a = genBoundInteger(integer);
            // Equivalent to: ((a^(integer - 1)) % integer) == 1)
            if (!a.modPow(integer.subtract(ONE), integer).equals(ONE)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Generate a number in the form of a string.
     *
     * @param digits the number of characters/digits in the generated string
     * @return A number {@code digits} long, where the first digit of the string will always be >= 1
     */
    public String numString(int digits) {
        if (digits < 1) {
            throw new IllegalArgumentException("The number of digits must be at least 1.");
        }

        StringBuilder builder = new StringBuilder();

        // Appends a number 1-9 to ensure the first digit is not 0
        builder.append(internalRand.nextInt(9) + 1);
        for (int i = 0; i < digits - 1; ++i) {
            // Appends a number 0-9
            builder.append(internalRand.nextInt(10));
        }
        return builder.toString();
    }
}
