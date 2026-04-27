package com.pwn_burp.burp;

import burp.*;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import com.google.gson.*;
import com.pwn_burp.api.models.ProxyListener;
import com.pwn_burp.api.models.ProxyHistoryMessage;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.*;

public class ProxyService {
    private final MontoyaApi api;
    private final Map<Integer, ProxyHistoryMessage> items = new HashMap<>();
    private final IBurpExtenderCallbacks callbacks;
    private final Gson gson = new Gson();

    public ProxyService(MontoyaApi api, IBurpExtenderCallbacks callbacks) {
        this.api = api;
        this.callbacks = callbacks;
        if (this.callbacks == null) {
            throw new IllegalArgumentException("IBurpExtenderCallbacks cannot be null");
        }
    }

    /**
     * RESILIENT, PAGINATED getProxyHistory — now returns MOST RECENT entries first.
     * offset=0 → newest 200 items (newest at index 0 of the JSON array).
     */
    public String getProxyHistory(String urlPrefix, int limit, int offset, String highlight) {
        final int MAX_LIMIT = 500;
        int effectiveLimit = Math.min(Math.max(limit, 1), MAX_LIMIT);
        int effectiveOffset = Math.max(0, offset);

        JsonArray maps = new JsonArray();
        int processed = 0;

        try {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            int total = history.size();

            // Start from the end of the list (newest items)
            for (int i = total - 1; i >= 0; i--) {
                ProxyHttpRequestResponse item = history.get(i);
                // If highlight filter is set, skip non-matching entries early
                if (highlight != null && !highlight.isEmpty() && !highlight.equals("NONE")) {
                    String itemHighlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                            ? item.annotations().highlightColor().toString() : "NONE";
                    if (!highlight.equalsIgnoreCase(itemHighlight)) {
                        continue;
                    }
                }

                if (processed < effectiveOffset) {
                    processed++;
                    continue;
                }

                if (maps.size() >= effectiveLimit) {
                    break;
                }

                // URL prefix filter
                if (!urlPrefix.isEmpty()) {
                    String url = (item.request() != null) ? item.request().url() : null;
                    if (url == null || !url.startsWith(urlPrefix)) {
                        continue;
                    }
                }

                try {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("id", i); // keep original index for reference

                    // Timing data
                    TimingData td = item.timingData();
                    if (td != null) {
                        obj.addProperty("time_between_request_sent_and_start_of_response", td.timeBetweenRequestSentAndStartOfResponse().toMillis());
                        obj.addProperty("time_between_request_sent_and_end_of_response", td.timeBetweenRequestSentAndEndOfResponse().toMillis());
                        obj.addProperty("time_request_sent", td.timeRequestSent().toString());
                    } else {
                        obj.addProperty("time_between_request_sent_and_start_of_response", -1);
                        obj.addProperty("time_between_request_sent_and_end_of_response", -1);
                        obj.addProperty("time_request_sent", "");
                    }

                    // Full bodies
                    String requestBase64 = item.request() != null
                            ? Base64.getEncoder().encodeToString(item.request().toByteArray().getBytes()) : null;
                    obj.addProperty("request", requestBase64);

                    String responseBase64 = item.response() != null
                            ? Base64.getEncoder().encodeToString(item.response().toByteArray().getBytes()) : null;
                    obj.addProperty("response", responseBase64);

                    // Annotations
                    String itemHighlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                            ? item.annotations().highlightColor().toString() : "";
                    obj.addProperty("highlight", itemHighlight);

                    String comment = (item.annotations() != null && item.annotations().notes() != null)
                            ? item.annotations().notes() : "";
                    obj.addProperty("comment", comment);

                    // HTTP Service
                    JsonObject serviceObj = new JsonObject();
                    HttpService httpService = item.httpService();
                    serviceObj.addProperty("host", httpService != null && httpService.host() != null ? httpService.host() : "");
                    serviceObj.addProperty("port", httpService != null ? httpService.port() : 0);
                    serviceObj.addProperty("protocol", httpService != null ? (httpService.secure() ? "https" : "http") : "");
                    obj.add("http_service", serviceObj);

                    maps.add(obj);
                } catch (Exception e) {
                    api.logging().logToError("Failed to process proxy history entry at index " + i + ": " + e.getMessage());
                }
                processed++;
            }
        } catch (Exception e) {
            api.logging().logToError("Critical error iterating proxy history: " + e.getMessage());
        }

        return maps.toString();
    }

    /**
     * Backward-compatibility overload.
     */
    public String getProxyHistory(String urlPrefix) {
        return getProxyHistory(urlPrefix, 200, 0, "NONE");
    }

    /**
     * RESILIENT, PAGINATED getWebSocketHistory — now returns MOST RECENT entries first.
     * offset=0 → newest 200 items (newest at index 0 of the JSON array).
     */
    public String getWebSocketHistory(String urlPrefix, int limit, int offset, String highlight) {
        final int MAX_LIMIT = 500;
        int effectiveLimit = Math.min(Math.max(limit, 1), MAX_LIMIT);
        int effectiveOffset = Math.max(0, offset);

        JsonArray maps = new JsonArray();
        int processed = 0;

        try {
            List<ProxyWebSocketMessage> wsHistory = api.proxy().webSocketHistory();
            int total = wsHistory.size();

            // Start from the end of the list (newest items)
            for (int i = total - 1; i >= 0; i--) {
                ProxyWebSocketMessage item = wsHistory.get(i);

                // If highlight filter is set, skip non-matching entries early
                if (highlight != null && !highlight.isEmpty() && !highlight.equals("NONE")) {
                    String itemHighlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                            ? item.annotations().highlightColor().toString() : "NONE";
                    if (!highlight.equalsIgnoreCase(itemHighlight)) {
                        continue;
                    }
                }

                if (processed < effectiveOffset) {
                    processed++;
                    continue;
                }

                if (maps.size() >= effectiveLimit) {
                    break;
                }

                try {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("id", i);

                    obj.addProperty("direction", item.direction() != null ? item.direction().toString() : "");

                    HttpRequest upgradeRequest = item.upgradeRequest();
                    if (upgradeRequest != null) {
                        String url = upgradeRequest.url();
                        obj.addProperty("url", url != null ? url : "");
                    } else {
                        obj.addProperty("url", "");
                    }

                    ZonedDateTime time_payload_sent = item.time();
                    obj.addProperty("time_payload_sent", time_payload_sent != null ? time_payload_sent.toString() : "");

                    String payloadBase64 = item.payload() != null
                            ? Base64.getEncoder().encodeToString(item.payload().getBytes()) : null;
                    obj.addProperty("payload", payloadBase64);

                    int listenerPort = item.listenerPort();
                    obj.addProperty("listener_port", listenerPort > 0 ? listenerPort : -1);

                    int webSocketId = item.webSocketId();
                    obj.addProperty("web_socket_id", webSocketId >= 0 ? webSocketId : -1);

                    String itemHighlight = (item.annotations() != null && item.annotations().highlightColor() != null)
                            ? item.annotations().highlightColor().toString() : "";
                    obj.addProperty("highlight", itemHighlight);

                    String comment = (item.annotations() != null && item.annotations().notes() != null)
                            ? item.annotations().notes() : "";
                    obj.addProperty("comment", comment);

                    maps.add(obj);
                } catch (Exception e) {
                    api.logging().logToError("Failed to process WebSocket history entry at index " + i + ": " + e.getMessage());
                }
                processed++;
            }
        } catch (Exception e) {
            api.logging().logToError("Critical error iterating WebSocket history: " + e.getMessage());
        }

        return maps.toString();
    }

    /**
     * Backward-compatibility overload.
     */
    public String getWebSocketHistory(String urlPrefix) {
        return getWebSocketHistory(urlPrefix, 200, 0, "NONE");
    }

    // === EVERYTHING BELOW THIS LINE IS UNCHANGED FROM YOUR LATEST FILE ===
    public void updateProxyHistoryEntry(int id, String notes, String color) {
        List<ProxyHttpRequestResponse> history = api.proxy().history();
        if (id < 0 || id >= history.size()) {
            api.logging().logToError("Invalid proxy history id: " + id);
            return;
        }
        ProxyHttpRequestResponse entry = history.get(id);
        HighlightColor hl = HighlightColor.NONE;
        if (color != null) {
            try {
                hl = HighlightColor.valueOf(color.toUpperCase());
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid highlight color: " + color + ". Using NONE.");
                hl = HighlightColor.NONE;
            }
        }
        Annotations annotations = entry.annotations();
        annotations.setNotes(notes);
        annotations.setHighlightColor(hl);
    }

    public void updateWebSocketHistoryEntry(int id, String notes, String color) {
        List<ProxyWebSocketMessage> history = api.proxy().webSocketHistory();
        if (id < 0 || id >= history.size()) {
            api.logging().logToError("Invalid proxy history id: " + id);
            return;
        }
        ProxyWebSocketMessage entry = history.get(id);
        HighlightColor hl = HighlightColor.NONE;
        if (color != null) {
            try {
                hl = HighlightColor.valueOf(color.toUpperCase());
            } catch (IllegalArgumentException e) {
                api.logging().logToError("Invalid highlight color: " + color + ". Using NONE.");
                hl = HighlightColor.NONE;
            }
        }
        Annotations annotations = entry.annotations();
        annotations.setNotes(notes);
        annotations.setHighlightColor(hl);
    }

    public void setProxyInterceptionEnabled(boolean enabled) {
        if (enabled) {
            api.proxy().enableIntercept();
        } else {
            api.proxy().disableIntercept();
        }
    }

    public List<ProxyListener> getProxyListeners() {
        try {
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listenersArray = proxy.getAsJsonArray("request_listeners");
            List<ProxyListener> listeners = new ArrayList<>();
            for (int i = 0; i < listenersArray.size(); i++) {
                JsonObject listenerJson = listenersArray.get(i).getAsJsonObject();
                String listenMode = listenerJson.get("listen_mode").getAsString();
                String bindAddress;
                if ("all_interfaces".equals(listenMode)) {
                    bindAddress = "*";
                } else if ("loopback_only".equals(listenMode)) {
                    bindAddress = "127.0.0.1";
                } else {
                    bindAddress = listenerJson.get("bindAddress").getAsString();
                }
                int port = listenerJson.get("listener_port").getAsInt();
                boolean enabled = listenerJson.get("running").getAsBoolean();
                listeners.add(new ProxyListener(String.valueOf(i), bindAddress, port, enabled));
            }
            return listeners;
        } catch (Exception e) {
            api.logging().logToError("Failed to get proxy listeners: " + e.getMessage());
            return new ArrayList<>();
        }
    }

    public boolean addProxyListener(String bindAddress, int port) {
        try {
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            JsonObject newListener = new JsonObject();
            String mode;
            if ("*".equals(bindAddress)) {
                mode = "all_interfaces";
            } else if ("127.0.0.1".equals(bindAddress)) {
                mode = "loopback_only";
            } else {
                mode = "specific_address";
                newListener.addProperty("bindAddress", bindAddress);
            }
            newListener.addProperty("listen_mode", mode);
            newListener.addProperty("listener_port", port);
            newListener.addProperty("running", true);
            newListener.addProperty("certificate_mode", "per_host");
            listeners.add(newListener);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to add proxy listener: " + e.getMessage());
            return false;
        }
    }

    public boolean updateProxyListener(String id, String bindAddress, int port) {
        try {
            int index = Integer.parseInt(id);
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            if (index < 0 || index >= listeners.size()) {
                return false;
            }
            JsonObject listener = listeners.get(index).getAsJsonObject();
            String mode;
            if ("*".equals(bindAddress)) {
                mode = "all_interfaces";
            } else if ("127.0.0.1".equals(bindAddress)) {
                mode = "loopback_only";
            } else {
                mode = "specific_address";
                listener.addProperty("bindAddress", bindAddress);
            }
            listener.addProperty("listen_mode", mode);
            listener.addProperty("listener_port", port);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to update proxy listener: " + e.getMessage());
            return false;
        }
    }

    public boolean deleteProxyListener(String id) {
        try {
            int index = Integer.parseInt(id);
            String configJson = callbacks.saveConfigAsJson("proxy.request_listeners");
            JsonObject root = gson.fromJson(configJson, JsonObject.class);
            JsonObject proxy = root.getAsJsonObject("proxy");
            JsonArray listeners = proxy.getAsJsonArray("request_listeners");
            if (index < 0 || index >= listeners.size()) {
                return false;
            }
            listeners.remove(index);
            callbacks.loadConfigFromJson(root.toString());
            return true;
        } catch (Exception e) {
            api.logging().logToError("Failed to delete proxy listener: " + e.getMessage());
            return false;
        }
    }
}
