package com.yubico.backend;

import com.yubico.exceptions.YubiHsmConnectionException;
import com.yubico.util.Utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Logger;

/**
 * Handles connection to the YubiHSM over HTTP
 */
public class HttpBackend implements Backend {

    private Logger logger = Logger.getLogger(HttpBackend.class.getName());

    private final String DEFAULT_URL = "http://localhost:12345/connector/api";
    private final int DEFAULT_TIMEOUT = 0;

    private URL url;
    private int timeout;
    private HttpURLConnection connection = null;

    public HttpBackend() throws MalformedURLException {
        this.url = new URL(DEFAULT_URL);
        this.timeout = DEFAULT_TIMEOUT;
    }

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
     * @throws YubiHsmConnectionException if connection fails
     */
    private HttpURLConnection getConnection() throws YubiHsmConnectionException {
        if (connection == null) {
            logger.finer("Opening HTTP connection to the device");
            HttpURLConnection conn;
            try {
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setConnectTimeout(timeout * 1000);
                conn.setRequestProperty("Content-Type", "application/octet-stream");
                connection = conn;
            } catch (IOException e) {
                throw new YubiHsmConnectionException(e);
            }
        }
        return connection;
    }

    /**
     * Sends an HTTP POST request to the device and gets a response
     *
     * @param message the data to send to the device
     * @return the device response
     * @throws YubiHsmConnectionException if connection to, writing to or reading from the device fail
     */
    public byte[] transceive(byte[] message) throws YubiHsmConnectionException {

        logger.finest("SEND >> " + Utils.getPrintableBytes(message));

        HttpURLConnection conn = getConnection();
        try {
            OutputStream out = conn.getOutputStream();
            out.write(message);
            out.flush();
            out.close();
        } catch (IOException e1) {
            throw new YubiHsmConnectionException(e1);
        }

        InputStream in;
        try {
            if (conn.getResponseCode() < 400) {
                logger.finer("Received HTTP response OK");
                in = conn.getInputStream();
            } else {
                logger.info("Received HTTP error response");
                in = conn.getErrorStream();
            }
        } catch (IOException e) {
            throw new YubiHsmConnectionException(e);
        }


        byte[] response;

        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            int len;
            byte[] buffer = new byte[2048];
            while (-1 != (len = in.read(buffer))) {
                bos.write(buffer, 0, len);
            }
            in.close();
            response = bos.toByteArray();
        } catch (IOException e) {
            throw new YubiHsmConnectionException(e);
        }
        close();
        logger.finest("RECEIVE: " + Utils.getPrintableBytes(response));

        return response;
    }

    /**
     * Closes the connection to the device if it is open
     */
    public void close() {
        if (connection != null) {
            connection.disconnect();
            connection = null;
        }
    }

}
