package com.pwn_burp.config;

import burp.api.montoya.logging.Logging;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ConfigManager {
    private final Logging logging;
    private String serverAddress = "127.0.0.1";
    private int serverPort = 1337;
    private String proxyAddress = "127.0.0.1";
    private int proxyPort = 8080;

    public ConfigManager(Logging logging) {
        this.logging = logging;
        loadConfig();
    }

    public void loadConfig() {
        Properties props = new Properties();
        try (InputStream stream = ConfigManager.class.getResourceAsStream("/config.properties")) {
            if (stream != null) {
                props.load(stream);
                serverAddress = props.getProperty("server.address", serverAddress);
                serverPort = Integer.parseInt(props.getProperty("server.port", String.valueOf(serverPort)));
                proxyAddress = props.getProperty("proxy.address", proxyAddress);
                proxyPort = Integer.parseInt(props.getProperty("proxy.port", String.valueOf(proxyPort)));
            } else {
                logging.logToError("config.properties not found on classpath; using defaults");
            }
        } catch (IOException | NumberFormatException e) {
            logging.logToError("Failed to load config: " + e.getMessage());
        }

        // Override with system properties if provided
        serverAddress = System.getProperty("server.address", serverAddress);
        String sPortStr = System.getProperty("server.port", String.valueOf(serverPort));
        try {
            serverPort = Integer.parseInt(sPortStr);
        } catch (NumberFormatException e) {
            logging.logToError("Invalid server.port system property: " + sPortStr);
        }

        proxyAddress = System.getProperty("proxy.address", proxyAddress);
        String pPortStr = System.getProperty("proxy.port", String.valueOf(proxyPort));
        try {
            proxyPort = Integer.parseInt(pPortStr);
        } catch (NumberFormatException e) {
            logging.logToError("Invalid proxy.port system property: " + pPortStr);
        }
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public int getServerPort() {
        return serverPort;
    }

    public String getProxyAddress() {
        return proxyAddress;
    }

    public int getProxyPort() {
        return proxyPort;
    }
}
