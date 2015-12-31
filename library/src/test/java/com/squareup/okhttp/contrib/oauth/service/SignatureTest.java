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

import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.contrib.oauth.OAuthConsumer;
import com.squareup.okhttp.contrib.oauth.consumer.DefaultOAuthConsumer;
import com.squareup.okhttp.contrib.oauth.request.OAuthRequest;
import com.squareup.okhttp.contrib.oauth.signing.NonceGenerator;
import com.squareup.okhttp.contrib.oauth.signing.TimestampGenerator;
import com.squareup.okhttp.contrib.oauth.token.DefaultToken;
import com.squareup.okhttp.contrib.oauth.token.Token;

import org.junit.Test;


import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test data from..
 *
 * @link https://dev.twitter.com/oauth/overview/authorizing-requests
 * @link https://dev.twitter.com/oauth/overview/creating-signatures
 */
public class SignatureTest {


    protected final String consumerKey = "xvz1evFS4wEEPTGEFPHBog";
    protected final String consumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    protected final String tokenValue = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
    protected final String tokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

    @Test
    public void testSignRequestWithTokenAndSecret() throws Exception {
        final OAuth10Service service = new OAuth10Service();
        service.nonce = new NonceGenerator() {
            @Override
            public String create() {
                return "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
            }
        };
        service.timestamp = new TimestampGenerator() {
            @Override
            public long create() {
                return 1318622958;
            }
        };

        final OAuthConsumer consumer = new DefaultOAuthConsumer(consumerKey, consumerSecret);
        final Token token = new DefaultToken(tokenValue, tokenSecret);

        final Request request = new Request.Builder()
                .url("https://api.twitter.com/1/statuses/update.json?include_entities=true")
                .post(new FormEncodingBuilder()
                        .add("status", "Hello Ladies + Gentlemen, a signed OAuth request!")
                        .build())
                .build();

        final OAuthRequest oAuthRequest = new OAuthRequest(request);

        final OAuthRequest authorized = service.authorizeRequest(oAuthRequest, consumer, token);


        assertThat(authorized).isNotNull();

        assertThat(authorized.oauth().get("oauth_signature"))
                .isEqualTo("tnnArxj06cWHq44gCs1OSKk/jLY=");

        assertThat(authorized.authorizedRequest().header("Authorization"))
                .isEqualTo("OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\""
                        + ", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\""
                        + ", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\""
                        + ", oauth_signature_method=\"HMAC-SHA1\""
                        + ", oauth_timestamp=\"1318622958\""
                        + ", oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\""
                        + ", oauth_version=\"1.0\"");
    }

/*
    @Test
    public void testSignRequestWithConsumerKeySecret() throws Exception {
        final RequestSigner signer = new RequestSigner.Builder()
                .consumer("cChZNFj6T5R0TigYB9yd1w", "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg")
                .nonce(new OAuth.NonceGenerator() {

                    @Override
                    public String create() {
                        return "ea9ec8429b68d6b77cd5600adbbb0456";
                    }
                })
                .timestamp(new OAuth.TimestampGenerator() {

                    @Override
                    public long create() {
                        return 1318467427;
                    }
                })
                .build();

        final OAuthRequest oAuthRequest = new OAuthRequest.Builder()
                .requestToken("POST", "https://api.twitter.com/oauth/request_token", "http://localhost/sign-in-with-twitter/")
                .build();

        final OAuthRequest signed = signer.signRequest(oAuthRequest);

        assertThat(signed).isNotNull();

        assertThat(signed.oauth().get("oauth_signature"))
                .isEqualTo("F1Li3tvehgcraF8DMJ7OyxO4w9Y=");
    }*/

}
