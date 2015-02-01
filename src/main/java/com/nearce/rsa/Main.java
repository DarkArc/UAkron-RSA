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

public class Main {

    public static void main(String[] args) {
        PairGenerator gen = new PairGenerator(10);
        KeyPair pair = gen.keyGen(50, 50);
        PublicKey pub = pair.getPublicKey();
        PrivateKey priv = pair.getPrivateKey();

        System.out.println("Pub n: " + pub.getN() + ", e: " + pub.getE());
        System.out.println("Priv n: " + priv.getN() + ", d: " + priv.getD());

        Encryptor encryptor = new Encryptor(pair);
        BigInteger encr = encryptor.encrypt("What's up man?");

        System.out.println(encryptor.decrypt(encr));
    }
}
