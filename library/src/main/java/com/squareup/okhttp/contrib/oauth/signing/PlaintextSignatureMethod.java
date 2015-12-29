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

import okio.Buffer;

public class PlaintextSignatureMethod implements SignatureMethod {

    private String consumerSecret;
    private String tokenSecret;

    @Override
    public SignatureMethod withKey(String consumerSecret, String tokenSecret) throws SigningException {
        this.consumerSecret = consumerSecret;
        this.tokenSecret = tokenSecret;

        return this;
    }

    @Override
    public String signatureOf(String baseString) throws SigningException {

        return new Buffer()
                .writeUtf8(PercentEncoder.encode(consumerSecret))
                .writeByte('&')
                .writeUtf8(PercentEncoder.encode(tokenSecret))
                .readUtf8();
    }

    @Override
    public String methodName() {
        return OAuth.SIGNATURE_METHOD_VALUE_PLAINTEXT;
    }

}
