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

import com.squareup.okhttp.Interceptor;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.contrib.oauth.OAuthService;
import com.squareup.okhttp.contrib.oauth.request.OAuthRequest;

import java.io.IOException;

/** OK HTTP interceptor that signs requests */
public class SigningInterceptor implements Interceptor {

    protected OAuthService service;

    @Override
    public Response intercept(Chain chain) throws IOException {
        final Request request = chain.request();
        if (service == null || request.header("X-OKHttp-OAuth-Authorized") != null) {
            return chain.proceed(request);
        }

        return chain.proceed(signed(request));
    }

    /** Returns a oauth-signed request */
    protected Request signed(Request request) throws SigningException {
        OAuthRequest req = new OAuthRequest(request);

        // TODO: need the token and consumer here ...
        return service.authorizeRequest(req, null, null).authorizedRequest();
    }

}
