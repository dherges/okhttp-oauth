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

package com.squareup.okhttp.contrib.oauth.service;

import com.squareup.okhttp.contrib.oauth.OAuth;
import com.squareup.okhttp.contrib.oauth.OAuthConsumer;
import com.squareup.okhttp.contrib.oauth.OAuthService;
import com.squareup.okhttp.contrib.oauth.encoder.PercentEncoder;
import com.squareup.okhttp.contrib.oauth.request.AuthorizationStrategy;
import com.squareup.okhttp.contrib.oauth.request.HeaderAuthorizationStrategy;
import com.squareup.okhttp.contrib.oauth.request.OAuthRequest;
import com.squareup.okhttp.contrib.oauth.signing.DefaultNonceGenerator;
import com.squareup.okhttp.contrib.oauth.signing.DefaultTimestampGenerator;
import com.squareup.okhttp.contrib.oauth.signing.HmacSha1SignatureMethod;
import com.squareup.okhttp.contrib.oauth.signing.NonceGenerator;
import com.squareup.okhttp.contrib.oauth.signing.SignatureMethod;
import com.squareup.okhttp.contrib.oauth.signing.SigningException;
import com.squareup.okhttp.contrib.oauth.signing.TimestampGenerator;
import com.squareup.okhttp.contrib.oauth.token.Token;

import java.util.SortedMap;
import java.util.TreeMap;

import okio.Buffer;

public class OAuth10Service implements OAuthService {

    protected AuthorizationStrategy authorizationStrategy = new HeaderAuthorizationStrategy();
    protected SignatureMethod signatureMethod = new HmacSha1SignatureMethod();
    protected TimestampGenerator timestamp = new DefaultTimestampGenerator();
    protected NonceGenerator nonce = new DefaultNonceGenerator();

    @Override
    public SignatureMethod signatureMethod() {
        return signatureMethod;
    }

    @Override
    public NonceGenerator nonceGenerator() {
        return nonce;
    }

    @Override
    public TimestampGenerator timestampGenerator() {
        return timestamp;
    }

    @Override
    public AuthorizationStrategy authorizationStrategy() {
        return authorizationStrategy;
    }

    @Override
    public OAuthRequest authorizeRequest(OAuthRequest request, OAuthConsumer consumer, Token token)
            throws SigningException {

        final OAuthRequest authorized = new OAuthRequest(request);

        // Build oauth_* params
        authorized.oauth(OAuth.CONSUMER_KEY, consumer.key());
        authorized.oauth(OAuth.NONCE, nonce.create());
        authorized.oauth(OAuth.SIGNATURE_METHOD, signatureMethod.methodName());
        authorized.oauth(OAuth.TIMESTAMP, "" + timestamp.create());
        if (token != null && token.value() != null && token.value().length() > 0) {
            authorized.oauth(OAuth.TOKEN, token.value());
        }
        authorized.oauth(OAuth.VERSION, OAuth.VERSION_VALUE_10);

        // Collect signing params, need to percent encode all the values
        final SortedMap<String, String> signingParams = new TreeMap<>();
        for (String key : request.oauth().keySet()) {
            signingParams.put(key, PercentEncoder.encode(request.oauth().get(key)));
        }
        for (String key : request.query().keySet()) {
            signingParams.put(key, PercentEncoder.encode(request.query().get(key)));
        }
        for (String key : request.body().keySet()) {
            signingParams.put(key, PercentEncoder.encode(request.body().get(key)));
        }

        // Create the parameter string
        final Buffer parameterString = new Buffer();
        for (String key : signingParams.keySet()) {
            if (parameterString.size() > 0) {
                parameterString.writeByte('&');
            }

            parameterString.writeUtf8(key)
                    .writeByte('=')
                    .writeUtf8(signingParams.get(key));
        }

        // Create the signature base string
        final Buffer signatureBaseString = new Buffer()
                .writeUtf8(request.verb())
                .writeByte('&')
                .writeUtf8(request.baseUrl())
                .writeByte('&')
                .writeUtf8(parameterString.readUtf8());

        // Create oauth_signature
        final String tokenSecret = (token != null) && token.secret() != null ? token.secret() : "";
        signatureMethod.withKey(consumer.secret(), tokenSecret);
        final String signature = signatureMethod.signatureOf(signatureBaseString.readUtf8());
        authorized.oauth(OAuth.SIGNATURE, signature);

        // Apply authorization to request
        authorizationStrategy.applyTo(authorized);

        return authorized;
    }
}
