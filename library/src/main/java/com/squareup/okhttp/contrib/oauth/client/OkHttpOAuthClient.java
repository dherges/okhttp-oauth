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

package com.squareup.okhttp.contrib.oauth.client;

import com.squareup.okhttp.Call;
import com.squareup.okhttp.FormEncodingBuilder;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.contrib.oauth.OAuth;
import com.squareup.okhttp.contrib.oauth.OAuthClient;
import com.squareup.okhttp.contrib.oauth.OAuthConsumer;
import com.squareup.okhttp.contrib.oauth.OAuthProvider;
import com.squareup.okhttp.contrib.oauth.OAuthService;
import com.squareup.okhttp.contrib.oauth.request.OAuthRequest;
import com.squareup.okhttp.contrib.oauth.signing.SignatureMethod;
import com.squareup.okhttp.contrib.oauth.signing.SigningException;
import com.squareup.okhttp.contrib.oauth.signing.SigningInterceptor;
import com.squareup.okhttp.contrib.oauth.token.DefaultToken;
import com.squareup.okhttp.contrib.oauth.token.Token;

public class OkHttpOAuthClient implements OAuthClient {

    protected OkHttpClient okHttpClient;
    protected OAuthConsumer consumer;
    protected OAuthProvider provider;
    protected OAuthService service;
    protected SigningInterceptor interceptor;
    protected SignatureMethod signatureMethod;

    public OkHttpOAuthClient(OkHttpClient okHttpClient, OAuthConsumer consumer, OAuthProvider provider, OAuthService service) {
        this.okHttpClient = okHttpClient;
        this.consumer = consumer;
        this.provider = provider;
        this.service = service;
        this.interceptor = new SigningInterceptor();

        okHttpClient.networkInterceptors().add(interceptor);
    }

    @Override
    public OkHttpClient okHttpClient() {
        return okHttpClient;
    }

    @Override
    public OAuthConsumer consumer() {
        return consumer;
    }

    @Override
    public OAuthProvider provider() {
        return provider;
    }

    @Override
    public Call newRequestToken(String callback) {
        Request req = new Request.Builder()
                .url(provider.requestTokenUrl())
                .method(provider.requestTokenVerb(), new FormEncodingBuilder().build())
                .header("X-OKHttp-OAuth-Authorized", "yes")
                .build();

        OAuthRequest orq = new OAuthRequest(req);
        try {
            OAuthRequest authReq = service.authorizeRequest(orq, consumer, null);

            return okHttpClient.newCall(authReq.authorizedRequest());
        } catch (SigningException e) {
            e.printStackTrace(); // TODO what to do now?!?
        }

        return null;
    }

    @Override
    public Call newAccessToken(String verifier) {
        Request req = new Request.Builder()
                .url(provider.requestTokenUrl())
                .method(
                        provider.requestTokenVerb(),
                        new FormEncodingBuilder()
                        .add(OAuth.VERIFIER, verifier)
                        .build()
                    )
                .build();

        OAuthRequest orq = new OAuthRequest(req);
        try {
            OAuthRequest authReq = service.authorizeRequest(orq, consumer, null);

            return okHttpClient.newCall(authReq.authorizedRequest());
        } catch (SigningException e) {
            e.printStackTrace(); // TODO what to do now?!?
        }

        return null;
    }

    @Override
    public void obtainedRequestToken(Response response) {
        // TODO: extract request token from response
        Token requestToken = new DefaultToken(response.message(), "");

        try {
            signatureMethod.withKey(consumer.secret(), requestToken.secret());
        } catch (SigningException e) {
            e.printStackTrace(); // TODO what to do now?!?
        }
    }

    @Override
    public void obtainedAccessToken(Response response) {
        // TODO: extract access token from response
        Token accessToken = new DefaultToken(response.message(), "");

        try {
            signatureMethod.withKey(consumer.secret(), accessToken.secret());
        } catch (SigningException e) {
            e.printStackTrace(); // TODO what to do now?!?
        }
    }

    @Override
    public Request sign(Request request) {
        return null;
    }

}
