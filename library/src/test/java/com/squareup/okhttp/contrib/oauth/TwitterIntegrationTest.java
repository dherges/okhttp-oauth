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

package com.squareup.okhttp.contrib.oauth;

import com.squareup.okhttp.Call;
import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Response;
import com.squareup.okhttp.contrib.oauth.client.OkHttpOAuthClient;
import com.squareup.okhttp.contrib.oauth.consumer.DefaultOAuthConsumer;
import com.squareup.okhttp.logging.HttpLoggingInterceptor;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class TwitterIntegrationTest {

    protected TwitterOAuth twitter;
    protected OAuthConsumer myConsumer;
    protected OAuthClient client;

    @Before
    public void setUp() {
        twitter = new TwitterOAuth();

        myConsumer = new DefaultOAuthConsumer("vp3R3eeSvXcYAJLot3TJOE1SJ", "qqI5GFRqJCnHFiIaK10gyVqDhrvGftZFUNIfO7bWGiSvhIyoM0");

        OkHttpClient okHttpClient = new OkHttpClient();
        HttpLoggingInterceptor log = new HttpLoggingInterceptor();
        log.setLevel(HttpLoggingInterceptor.Level.BODY);
        okHttpClient.networkInterceptors().add(log);
        client = new OkHttpOAuthClient(okHttpClient, myConsumer, twitter, twitter);
    }

    @Test
    public void testStuff() throws IOException {

        Call call = client.newRequestToken("oob");
        Response response = call.execute();

        assertThat(response.code()).isEqualTo(200);

        assertThat(response.body().string()).isNull();
    }




}
