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
import com.squareup.okhttp.contrib.oauth.OAuth;
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
public class OAuth10ServiceTest {

    private interface TestA {

        String CONSUMER_KEY = "xvz1evFS4wEEPTGEFPHBog";
        String CONSUMER_SECRET = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
        String TOKEN_VALUE = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
        String TOKEN_SECRET = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
        String NONCE = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
        long TIME = 1318622958;
    }

    private interface TestB {

        String CONSUMER_KEY = "cChZNFj6T5R0TigYB9yd1w";
        String CONSUMER_SECRET = "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg";
        String NONCE = "ea9ec8429b68d6b77cd5600adbbb0456";
        long TIME = 1318467427;
    }

    private interface TestC {

        String CONSUMER_KEY = TestB.CONSUMER_KEY;
        String CONSUMER_SECRET = TestB.CONSUMER_SECRET;
        String TOKEN_VALUE = "NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0";
        String TOKEN_SECRET = "veNRnAWe6inFuo8o2u8SLLZLjolYDmDP7SzL0YfYI";
        String NONCE = "a9900fe68e2573b27a37f10fbad6a755";
        long TIME = TestB.TIME;
    }


    /** https://dev.twitter.com/oauth/overview/creating-signatures */
    @Test
    public void authorizeRequestWithToken() throws Exception {
        final OAuthConsumer consumer = new DefaultOAuthConsumer(TestA.CONSUMER_KEY, TestA.CONSUMER_SECRET);
        final Token token = new DefaultToken(TestA.TOKEN_VALUE, TestA.TOKEN_SECRET);
        final OAuth10Service service = new OAuth10Service();
        service.nonce = new NonceGenerator() {
            @Override
            public String create() {
                return TestA.NONCE;
            }
        };
        service.timestamp = new TimestampGenerator() {
            @Override
            public long create() {
                return TestA.TIME;
            }
        };

        final OAuthRequest oAuthRequest = new OAuthRequest(new Request.Builder()
                .url("https://api.twitter.com/1/statuses/update.json?include_entities=true")
                .post(new FormEncodingBuilder()
                        .add("status", "Hello Ladies + Gentlemen, a signed OAuth request!")
                        .build())
                .build());

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


    /** https://dev.twitter.com/web/sign-in/implementing --> Step 1: Obtaining a request token */
    @Test
    public void authorizeRequestWithoutToken() throws Exception {
        final OAuthConsumer consumer = new DefaultOAuthConsumer(TestB.CONSUMER_KEY, TestB.CONSUMER_SECRET);
        final OAuth10Service service = new OAuth10Service();
        service.nonce = new NonceGenerator() {
            @Override
            public String create() {
                return TestB.NONCE;
            }
        };
        service.timestamp = new TimestampGenerator() {
            @Override
            public long create() {
                return TestB.TIME;
            }
        };

        final OAuthRequest oAuthRequest = new OAuthRequest(
                new Request.Builder()
                .url("https://api.twitter.com/oauth/request_token")
                .method("POST", new FormEncodingBuilder()
                        .add(OAuth.CALLBACK, "http://localhost/sign-in-with-twitter/")
                        .build())
                .build());

        final OAuthRequest authorized = service.authorizeRequest(oAuthRequest, consumer, null);


        assertThat(authorized).isNotNull();

        assertThat(authorized.oauth().get("oauth_signature"))
                .isEqualTo("F1Li3tvehgcraF8DMJ7OyxO4w9Y=");
    }


    /** https://dev.twitter.com/web/sign-in/implementing --> Step 3: Converting the request token to an access token */
    @Test
    public void authorizeRequestWithToken2() throws Exception {
        final OAuthConsumer consumer = new DefaultOAuthConsumer(TestC.CONSUMER_KEY, TestC.CONSUMER_SECRET);
        final Token token = new DefaultToken(TestC.TOKEN_VALUE, TestC.TOKEN_SECRET);
        final OAuth10Service service = new OAuth10Service();
        service.nonce = new NonceGenerator() {
            @Override
            public String create() {
                return TestC.NONCE;
            }
        };
        service.timestamp = new TimestampGenerator() {
            @Override
            public long create() {
                return TestC.TIME;
            }
        };

        final OAuthRequest oAuthRequest = new OAuthRequest(
                new Request.Builder()
                        .url("https://api.twitter.com/oauth/access_token")
                        .method("POST", new FormEncodingBuilder()
                                .add(OAuth.VERIFIER, "uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY")
                                .build())
                        .build());

        final OAuthRequest authorized = service.authorizeRequest(oAuthRequest, consumer, null);


        assertThat(authorized).isNotNull();

        assertThat(authorized.oauth().get("oauth_signature"))
                .isEqualTo("39cipBtIOHEEnybAR4sATQTpl2I=");
    }

}
