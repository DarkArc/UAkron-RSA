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

public class KeyPair {
    private final PublicKey pub;
    private final PrivateKey priv;

    public KeyPair(PublicKey pub, PrivateKey priv) {
        this.pub = pub;
        this.priv = priv;
    }

    public PublicKey getPublicKey() {
        return pub;
    }

    public PrivateKey getPrivateKey() {
        return priv;
    }
}
