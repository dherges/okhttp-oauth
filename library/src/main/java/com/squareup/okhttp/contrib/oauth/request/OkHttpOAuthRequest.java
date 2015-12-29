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

package com.squareup.okhttp.contrib.oauth.request;

import com.squareup.okhttp.HttpUrl;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.RequestBody;
import com.squareup.okhttp.contrib.oauth.encoder.PercentEncoder;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import okio.Buffer;

public class OkHttpOAuthRequest extends OAuthRequest2<Request> {
    private static final MediaType FORM_CONTENT_TYPE =
            MediaType.parse("application/x-www-form-urlencoded");

    protected SortedMap<String, String> oAuthParams = new TreeMap<>();

    public OkHttpOAuthRequest(Request request) {
        super(request);
    }

    @Override
    public String verb() {
        return wrapped.method();
    }

    @Override
    public String baseUrl() {
        return wrapped.httpUrl().newBuilder().query(null).fragment(null).build().toString();
    }

    @Override
    public Map<String, String> oauth() {
        return Collections.unmodifiableMap(oAuthParams);
    }

    @Override
    public void oauth(String key, String value) {
        oAuthParams.put(key, value);
    }

    @Override
    public String oauth(String key) {
        return oAuthParams.get(key);
    }

    @Override
    public Map<String, String> query() {
        return Collections.unmodifiableMap(extractQueryParams(wrapped));
    }

    @Override
    public Map<String, String> body() {
        return Collections.unmodifiableMap(extractBodyParams(wrapped.body()));
    }

    @Override
    public Request request() {
        return wrapped;
    }



    static Map<String, String> extractBodyParams(RequestBody body) {
        // extract form-encoded HTTP body params
        final Map<String, String> bodyParams = new HashMap<>();
        if (body != null && body.contentType().equals(FORM_CONTENT_TYPE)) {
            final Buffer buffer = new Buffer();
            try {
                body.writeTo(buffer);

                while (!buffer.exhausted()) {
                    long keyEnd = buffer.indexOf((byte) '=');
                    if (keyEnd == -1)
                        throw new IllegalStateException("Key with no value: " + buffer.readUtf8());
                    String key = buffer.readUtf8(keyEnd);
                    buffer.skip(1); // Equals.

                    long valueEnd = buffer.indexOf((byte) '&');
                    String value = valueEnd == -1 ? buffer.readUtf8() : buffer.readUtf8(valueEnd);
                    if (valueEnd != -1) buffer.skip(1); // Ampersand.

                    bodyParams.put(key, value);
                }
            } catch (IOException e) {
            }
        }

        return bodyParams;
    }

    static Map<String, String> extractQueryParams(Request request) {
        // extract HTTP query params
        final HttpUrl url = request.httpUrl();
        final Map<String, String> queryParams = new HashMap<>(url.querySize());
        for (int i = 0, len = url.querySize(); i < len; i++) {
            final String key = PercentEncoder.encode(url.queryParameterName(i));
            final String value = PercentEncoder.encode(url.queryParameterValue(i));

            queryParams.put(key, value);
        }

        return queryParams;
    }
}
