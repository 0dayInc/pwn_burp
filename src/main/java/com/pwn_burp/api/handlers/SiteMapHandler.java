package com.pwn_burp.api.handlers;

import com.google.gson.*;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;

import java.util.Base64;

public class SiteMapHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public SiteMapHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/sitemap", this::getAllSiteMap);
        server.get("/sitemap/{url}", this::getSiteMapByUrl);
        server.post("/sitemap", this::addToSiteMap);
        server.put("/sitemap", this::updateSiteMap);
    }

    @OpenApi(
        summary = "Get all site map entries (paginated)",
        operationId = "getAllSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.GET},
        queryParams = {
            @OpenApiParam(
                name = "limit",
                description = "Maximum number of items to return (capped at 500)",
                required = false,
                type = Integer.class,
                example = "200"
            ),
            @OpenApiParam(
                name = "offset",
                description = "Number of items to skip (for pagination)",
                required = false,
                type = Integer.class,
                example = "0"
            ),
            @OpenApiParam(
                name = "highlight",
                description = "Filter entries by highlight color (e.g., RED, BLUE, GREEN)",
                required = false,
                type = String.class,
                example = "RED"
            )
        },
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of site map entries",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}]"
                    )
                }
            )
        }
    )
    private void getAllSiteMap(Context ctx) {
        String urlPrefix = "";
        int limit  = ctx.queryParamAsClass("limit", Integer.class).getOrDefault(200);
        int offset = ctx.queryParamAsClass("offset", Integer.class).getOrDefault(0);
        String highlight = ctx.queryParamAsClass("highlight", String.class).getOrDefault("NONE");

        ctx.status(200);
        respondWithJsonString(ctx, pwnService.getSiteMap(urlPrefix, limit, offset, highlight));
    }

    @OpenApi(
        summary = "Get site map entries for a specific Base64-encoded URL prefix (paginated)",
        operationId = "getSiteMapByUrl",
        path = "/sitemap/{url}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL prefix", required = true)},
        queryParams = {
            @OpenApiParam(
                name = "limit",
                description = "Maximum number of items to return (capped at 500)",
                required = false,
                type = Integer.class,
                example = "200"
            ),
            @OpenApiParam(
                name = "offset",
                description = "Number of items to skip (for pagination)",
                required = false,
                type = Integer.class,
                example = "0"
            ),
            @OpenApiParam(
                name = "highlight",
                description = "Filter entries by highlight color (e.g., RED, BLUE, GREEN)",
                required = false,
                type = String.class,
                example = "RED"
            )
        },
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "List of site map entries",
                content = {
                    @OpenApiContent(
                        from = SiteMapMessage[].class,
                        mimeType = "application/json",
                        example = "[{\n" +
                                  "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                                  "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                                  "  \"highlight\": \"BLUE\",\n" +
                                  "  \"comment\": \"Example sitemap entry\",\n" +
                                  "  \"http_service\": {\n" +
                                  "    \"host\": \"example.com\",\n" +
                                  "    \"port\": 443,\n" +
                                  "    \"protocol\": \"https\"\n" +
                                  "  }\n" +
                                  "}]"
                    )
                }
            )
        }
    )
    private void getSiteMapByUrl(Context ctx) {
        String encodedUrl = ctx.pathParam("url") != null ? ctx.pathParam("url") : "";
        String urlPrefix;
        try {
            urlPrefix = new String(Base64.getDecoder().decode(encodedUrl));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", "Invalid Base64-encoded URL prefix"));
            return;
        }

        int limit  = ctx.queryParamAsClass("limit", Integer.class).getOrDefault(200);
        int offset = ctx.queryParamAsClass("offset", Integer.class).getOrDefault(0);
        String highlight = ctx.queryParamAsClass("highlight", String.class).getOrDefault("NONE");

        ctx.status(200);
        respondWithJsonString(ctx, pwnService.getSiteMap(urlPrefix, limit, offset, highlight));
    }

    @OpenApi(
        summary = "Add an entry to the site map",
        operationId = "addToSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(
            content = {
                @OpenApiContent(
                    from = SiteMapMessage.class,
                    mimeType = "application/json",
                    example = "{\n" +
                              "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                              "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                              "  \"highlight\": \"BLUE\",\n" +
                              "  \"comment\": \"Example sitemap entry\",\n" +
                              "  \"http_service\": {\n" +
                              "    \"host\": \"example.com\",\n" +
                              "    \"port\": 443,\n" +
                              "    \"protocol\": \"https\"\n" +
                              "  }\n" +
                              "}"
                )
            }
        ),
        responses = {
            @OpenApiResponse(
                status = "201",
                description = "Site map entry added"
            )
        }
    )
    private void addToSiteMap(Context ctx) {
        try {
            SiteMapMessage message = gson.fromJson(ctx.body(), SiteMapMessage.class);
            pwnService.addToSiteMap(message);
            ctx.status(201);
            ctx.json(message);
        } catch (Exception e) {
            ctx.status(400).json(pwnService.apiError("error", e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Update an entry in the site map",
        operationId = "updateSiteMap",
        path = "/sitemap",
        methods = {HttpMethod.PUT},
        requestBody = @OpenApiRequestBody(
            content = {
                @OpenApiContent(
                    from = SiteMapMessage.class,
                    mimeType = "application/json",
                    example = "{\n" +
                              "  \"request\": \"R0VUIC9hcGkvcGluZyBIVFRQLzEuMVxyXG5Ib3N0OiBleGFtcGxlLmNvbVxyXG5Vc2VyLUFnZW50OiBQV04vMS4wXHJcbkFjY2VwdDogYXBwbGljYXRpb24vanNvblxyXG5cclxu\",\n" +
                              "  \"response\": \"SFRUUC8xLjEgMjAwIE9LXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5Db250ZW50LUxlbmd0aDogMjFcbkRhdGU6IFdlZCwgMzAgSnVsIDIwMjUgMTY6MDA6MDAgR01UXHJcbkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvblxyXG5cclxueyJtZXNzYWdlIjogIlBPTkcifQ==\",\n" +
                              "  \"highlight\": \"BLUE\",\n" +
                              "  \"comment\": \"Example sitemap entry\",\n" +
                              "  \"http_service\": {\n" +
                              "    \"host\": \"example.com\",\n" +
                              "    \"port\": 443,\n" +
                              "    \"protocol\": \"https\"\n" +
                              "  }\n" +
                              "}"
                )
            }
        ),
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "Site map entry updated"
            )
        }
    )
    private void updateSiteMap(Context ctx) {
        try {
            SiteMapMessage message = gson.fromJson(ctx.body(), SiteMapMessage.class);
            pwnService.updateSiteMap(message);
            ctx.status(200);
            ctx.json(message);
        } catch (Exception e) {
            ctx.status(400).json(pwnService.apiError("error", e.getMessage()));
        }
    }

    private void respondWithJsonString(Context ctx, String json) {
        ctx.contentType("application/json");
        ctx.result(json == null ? "{}" : json);
    }
}
