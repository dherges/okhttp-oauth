/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 David Herges // https://github.com/dherges
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.squareup.okhttp.contrib.oauth.signing;


import com.squareup.okhttp.contrib.oauth.OAuth;
import com.squareup.okhttp.contrib.oauth.encoder.PercentEncoder;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import okio.Buffer;
import okio.ByteString;

public class HmacSha1SignatureMethod implements SignatureMethod {
    private static final String SIGNATURE_TYPE = "HmacSHA1";

    protected Mac mac;

    protected Buffer createKey(String consumerSecret, String tokenSecret) {
        final Buffer key = new Buffer()
                .writeUtf8(PercentEncoder.encode(consumerSecret))
                .writeByte('&');
        if (tokenSecret != null && tokenSecret.length() > 0) {
            key.writeUtf8(PercentEncoder.encode(tokenSecret));
        }

        return key;
    }

    protected Mac createMac(Buffer key) throws NoSuchAlgorithmException, InvalidKeyException {
        final SecretKeySpec secret = new SecretKeySpec(key.readByteArray(), SIGNATURE_TYPE);
        final Mac mac = Mac.getInstance(SIGNATURE_TYPE);
        mac.init(secret);

        return mac;
    }

    @Override
    public SignatureMethod withKey(String consumerSecret, String tokenSecret) throws SigningException {
        try {
            Buffer key = createKey(consumerSecret, tokenSecret);
            mac = createMac(key);
        } catch (NoSuchAlgorithmException e) {
            throw new SigningException("Algorithm not supported", e);
        } catch (InvalidKeyException e) {
            throw new SigningException("Invalid key", e);
        }


        return this;
    }

    @Override
    public String signatureOf(String baseString) {
        final ByteString signature = ByteString.of(mac.doFinal(baseString.getBytes()));

        return signature.base64();
    }

    @Override
    public String methodName() {
        return OAuth.SIGNATURE_METHOD_VALUE_HMAC_SHA1;
    }

}
