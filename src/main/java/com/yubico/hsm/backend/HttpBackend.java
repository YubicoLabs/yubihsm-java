package com.yubico.hsm.backend;

import com.yubico.hsm.exceptions.YHConnectionException;
import com.yubico.hsm.internal.util.Utils;
import lombok.NonNull;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.logging.Logger;

/**
 * Handles connection to the YubiHSM over HTTP
 */
public class HttpBackend implements Backend {
    private Logger log = Logger.getLogger(HttpBackend.class.getName());

    private final String DEFAULT_URL = "http://localhost:12345/connector/api";
    private final int DEFAULT_TIMEOUT = 0;
    private final int MAX_MESSAGE_SIZE = 2048;

    private URL url;
    private int timeout;
    private HttpURLConnection connection = null;

    /**
     * Default constructor. Connects to the YubiHSM using `http://localhost:12345/connector/api` and timeout `0`
     *
     * @throws MalformedURLException
     */
    public HttpBackend() throws MalformedURLException {
        this.url = new URL(DEFAULT_URL);
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
            this.url = new URL(DEFAULT_URL);
        }

        if (timeout > 0) {
            this.timeout = timeout;
        } else {
            this.timeout = DEFAULT_TIMEOUT;
        }
    }

    /**
     * Opens an HTTP connection to the YubiHSM device if a connection does not already exist
     *
     * @return HTTP connection to the YubiHSM device
     * @throws YHConnectionException if connection fails
     */
    private HttpURLConnection getConnection() throws YHConnectionException {
        if (connection == null) {
            log.finer("Opening HTTP connection to the device");
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

        if(message.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException("The message to send is too long. The message can at most be " + MAX_MESSAGE_SIZE + " bytes long but" +
                                               " was " + message.length + " bytes");
        }

        log.finest("SEND >> " + Utils.getPrintableBytes(message));

        byte[] response;
        HttpURLConnection conn = getConnection();
        try {
            try {
                OutputStream out = conn.getOutputStream();
                out.write(message);
                out.flush();
                out.close();
            } catch (IOException e1) {
                throw new YHConnectionException(e1);
            }

            BufferedInputStream bin;
            try {
                final int httpRespCode = conn.getResponseCode();
                if (httpRespCode == HttpURLConnection.HTTP_OK) {
                    log.finer("Received HTTP response OK");
                    bin = new BufferedInputStream(conn.getInputStream());
                } else {
                    log.info("Received HTTP error response " + httpRespCode);
                    bin = new BufferedInputStream(conn.getErrorStream());
                }
            } catch (IOException e) {
                throw new YHConnectionException(e);
            }

            byte[] buffer = new byte[MAX_MESSAGE_SIZE];
            int len;
            try {
                len = bin.read(buffer);
                bin.close();
            } catch (IOException e) {
                throw new YHConnectionException(e);
            }

            if(len < 0) {
                throw new YHConnectionException();
            }
            response = Arrays.copyOfRange(buffer, 0, len);

        } finally {
            close();
        }
        log.finest("RECEIVE: " + Utils.getPrintableBytes(response));
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

}
