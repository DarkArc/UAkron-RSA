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

import static java.math.BigInteger.ZERO;

public class Encryptor {
    private static final BigInteger C_128 = new BigInteger("128");

    private final KeyPair keyPair;

    /**
     * Constructs an Encryptor object which will use the given {@link com.nearce.rsa.internal.KeyPair}
     * for its lifetime.
     *
     * @param keyPair the {@link com.nearce.rsa.internal.KeyPair} which will be used
     */
    public Encryptor(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Encrypts the given {@link java.lang.String} as an integer using the {@link com.nearce.rsa.internal.PublicKey}
     * provided in the {@link com.nearce.rsa.internal.KeyPair} used to create the current instance.
     *
     * @param message the message to be encrypted
     * @return a {@link java.lang.String} representation of the created integer
     */
    public String encryptToString(String message) {
        return encrypt(message).toString();
    }

    /**
     * Encrypts the given string as an integer using the {@link com.nearce.rsa.internal.PublicKey}
     * provided in the {@link com.nearce.rsa.internal.KeyPair} used to create the current instance.
     *
     * @param message the message to be encrypted
     * @return a {@link java.math.BigInteger} representation of the created integer
     */
    public BigInteger encrypt(String message) {
        // Message ^ e mod n
        PublicKey key = keyPair.getPublicKey();
        return serialize(message).modPow(key.getE(), key.getN());
    }

    /**
     * Serializes the given message into an integer to be obscured during encryption.
     *
     * @param message the {@link java.lang.String} to convert
     * @return the {@link java.math.BigInteger} representation of the {@link java.lang.String}
     */
    private BigInteger serialize(String message) {
        BigInteger b = ZERO;
        for (int i = message.length() - 1; i >= 0; --i) {
            // Get the ASCII, then multiply by 128 ^ i, then add back to b
            b = b.add(new BigInteger(String.valueOf((short) message.charAt(i))).multiply(C_128.pow(i)));
        }
        return b;
    }

    /**
     * Decrypts the given encrypted integer {@link java.lang.String} into its original text.
     *
     * @param message the numeric {@link java.lang.String} to decrypt
     * @return the original message
     */
    public String decrypt(String message) {
        return decrypt(new BigInteger(message));
    }

    /**
     * Decrypts the given encrypted integer into its original text.
     *
     * @param iMessage the {@link java.math.BigInteger} to decrypt
     * @return the original message
     */
    public String decrypt(BigInteger iMessage) {
        // Message ^ d mod n
        PrivateKey key = keyPair.getPrivateKey();
        return deserialize(iMessage.modPow(key.getD(), key.getN()));
    }

    /**
     * Takes an unencrypted integer representation of a message, and returns it to its
     * original message.
     *
     * @param iMessage the {@link java.math.BigInteger} to reinterpret
     * @return the original message
     */
    private String deserialize(BigInteger iMessage) {
        StringBuilder b = new StringBuilder();
        BigInteger r;
        for (int k = 0; (r = iMessage.divide(C_128.pow(k))).compareTo(ZERO) != 0; ++k) {
            b.append((char) (r.mod(C_128).intValue()));
        }
        return b.toString();
    }
}
