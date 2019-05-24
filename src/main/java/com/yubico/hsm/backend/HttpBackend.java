/*
 * Copyright 2019 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.hsm.backend;

import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.internal.util.Utils;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.MissingResourceException;

/**
 * Handles connection to the YubiHSM over HTTP
 */
@Slf4j
public class HttpBackend implements Backend {

    private static final String DEFAULT_CONNECTOR_URL_ENV = "DEFAULT_CONNECTOR_URL";

    private static final String DEFAULT_URL = System.getenv(DEFAULT_CONNECTOR_URL_ENV);
    private static final int DEFAULT_TIMEOUT = 0;
    private static final int MAX_MESSAGE_SIZE = 2048;

    private URL url;
    private int timeout;
    private HttpURLConnection connection = null;

    /**
     * Default constructor. Connects to the YubiHSM using the URL specified in the environment variable DEFAULT_CONNECTOR_URL and timeout `0`
     *
     * @throws MalformedURLException
     */
    public HttpBackend() throws MalformedURLException {
        this.url = getDefaultConnectorUrl();
        this.timeout = DEFAULT_TIMEOUT;
    }

    /**
     * @param urlStr  URL used to connect to the YubiHSM over HTTP
     * @param timeout Connection timeout
     * @throws MalformedURLException
     */
    public HttpBackend(final String urlStr, final int timeout) throws MalformedURLException {
        if (urlStr != null && !urlStr.equals("")) {
            this.url = new URL(urlStr);
        } else {
            this.url = getDefaultConnectorUrl();
        }

        if (timeout > 0) {
            this.timeout = timeout;
        } else {
            this.timeout = DEFAULT_TIMEOUT;
        }
    }

    private URL getDefaultConnectorUrl() throws MalformedURLException {
        if (DEFAULT_URL == null || DEFAULT_URL.equals("")) {
            throw new IllegalStateException(
                    "If the URL to the YubiHSM connector is not specified, the environment variable '" + DEFAULT_CONNECTOR_URL_ENV + "' must be set");
        }
        return new URL(DEFAULT_URL);
    }

    /**
     * Opens an HTTP connection to the YubiHSM device if a connection does not already exist
     *
     * @return HTTP connection to the YubiHSM device
     * @throws YHConnectionException if connection fails
     */
    private HttpURLConnection getConnection() throws YHConnectionException {
        if (connection == null) {
            log.debug("Opening HTTP connection to the device");
            HttpURLConnection conn;
            try {
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout(timeout * 1000);
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                connection = conn;
            } catch (IOException e) {
                throw new YHConnectionException(e);
            }
        }
        return connection;
    }

    /**
     * Sends an HTTP POST request to the device and gets a response
     *
     * @param message the request payload to send to the device
     * @return the device response
     * @throws YHConnectionException if connection to, writing to or reading from the device fail
     */
    @Override
    public byte[] transceive(@NonNull byte[] message) throws YHConnectionException {

        if (message.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException("The message to send is too long. The message can at most be " + MAX_MESSAGE_SIZE + " bytes long but" +
                                               " was " + message.length + " bytes");
        }

        log.debug("SEND >> " + Utils.getPrintableBytes(message));

        byte[] response;
        HttpURLConnection conn = getConnection();
        try {
            sendHttpRequestMessage(conn, message);
            BufferedInputStream bin = getConnectionInputStream(conn);
            response = getHttpResponse(bin);
        } finally {
            close();
        }
        log.debug("RECEIVE: " + Utils.getPrintableBytes(response));
        return response;
    }

    /**
     * Closes the connection to the device if it is open
     */
    @Override
    public void close() {
        if (connection != null) {
            connection.disconnect();
            connection = null;
        }
    }

    private void sendHttpRequestMessage(@NonNull final HttpURLConnection connection, @NonNull final byte[] message) throws YHConnectionException {
        try {
            OutputStream out = connection.getOutputStream();
            out.write(message);
            out.flush();
            out.close();
        } catch (IOException e1) {
            log.error("Failed to send message to device");
            throw new YHConnectionException(e1);
        }
    }

    private BufferedInputStream getConnectionInputStream(@NonNull final HttpURLConnection connection) throws YHConnectionException {
        BufferedInputStream bin;
        try {
            final int httpRespCode = connection.getResponseCode();
            if (httpRespCode == HttpURLConnection.HTTP_OK) {
                log.debug("Received HTTP response OK");
                bin = new BufferedInputStream(connection.getInputStream());
            } else {
                log.debug("Received HTTP error response " + httpRespCode);
                bin = new BufferedInputStream(connection.getErrorStream());
            }
        } catch (IOException e) {
            log.error("Failed to obtain HTTP connection input stream");
            throw new YHConnectionException(e);
        }
        return bin;
    }

    private byte[] getHttpResponse(@NonNull final BufferedInputStream bin) throws YHConnectionException {
        byte[] buffer = new byte[MAX_MESSAGE_SIZE];
        int len;
        try {
            len = bin.read(buffer);
            bin.close();
            if (len < 0) {
                log.error("Failed to read HTTP response from device");
                throw new YHConnectionException();
            }
        } catch (IOException e) {
            log.error("Failed to read HTTP response from device");
            throw new YHConnectionException(e);
        }
        return Arrays.copyOfRange(buffer, 0, len);
    }

}
