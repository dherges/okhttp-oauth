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

/**
 * Abstraction for creating oauth signatures
 */
public interface SignatureMethod {

    /**
     * Initializes the signing key used by this instance.
     *
     * @param consumerSecret Consumer secret
     * @param tokenSecret Token secret
     * @return Self instance for method chaining
     * @throws SigningException
     */
    SignatureMethod withKey(String consumerSecret, String tokenSecret) throws SigningException;

    /**
     * Creates a signature of the given base string.
     *
     * @param baseString Base string input
     * @return Signature string
     * @throws SigningException
     */
    String signatureOf(String baseString) throws SigningException;

    /**
     * Returns the name of the signature method
     *
     * @return Example values: 'HMAC-SHA1', 'RSA-SHA1', 'PLAINTEXT'
     */
    String methodName();
}
