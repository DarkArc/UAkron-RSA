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

package com.nearce.rsa;

import com.nearce.rsa.internal.*;

import java.math.BigInteger;

import static java.lang.System.out;
import static java.math.BigInteger.ONE;

public class Main {

    // The number of times to check the prime number with Fermat's little theorem
    private static final int CHECK_THRESHOLD = 10;

    public static void main(String[] args) {
        PairGenerator generator = new PairGenerator(CHECK_THRESHOLD);

        // Forward declaration of all used variables
        int digits;
        String identifier;
        StringBuilder builder;
        BigInteger[] res;
        BigInteger e, a, b, p, q, n, d;
        Encryptor encryptor;

        // Command handling
        switch (args.length) {
            case 1:
                digits = Integer.parseInt(args[0]);
                out.println("Prime integer with " + digits + " digits: " + generator.getPrime(digits, CHECK_THRESHOLD));
                break;
            case 2:
                a = new BigInteger(args[0]);
                b = new BigInteger(args[1]);

                res = generator.extendedEuclidean(a, b);
                out.println("GCD: " + res[0] + ", X: " + res[1] + ", Y: " + res[2]);
                break;
            case 3:
                e = new BigInteger(args[0]);
                p = new BigInteger(args[1]);
                q = new BigInteger(args[2]);

                out.println("N: " + p.multiply(q) + ", Inverse: " + generator.findD(e, p.subtract(ONE).multiply(q.subtract(ONE))));
                break;
            case 4:
                identifier = args[0];
                n = new BigInteger(args[2]);
                builder = new StringBuilder();
                for (int i = 3; i < args.length; ++i) {
                    if (i > 3) {
                        builder.append(' ');
                    }
                    builder.append(args[i]);
                }
                switch (identifier) {
                    case "e":
                        e = new BigInteger(args[1]);
                        encryptor = new Encryptor(new KeyPair(new PublicKey(n, e), null));
                        out.println("Encrypted result: " + encryptor.encrypt(builder.toString()));
                        break;
                    case "d":
                        d = new BigInteger(args[1]);
                        encryptor = new Encryptor(new KeyPair(null, new PrivateKey(n, d)));
                        out.println("Decrypted result: " + encryptor.decrypt(builder.toString()));
                        break;
                }
                break;
            default:
                throw new IllegalArgumentException("Incorrect number of arguments.");
        }
    }
}
