package com.pwn_burp.api.handlers;

import com.google.gson.*;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;
import java.net.*;
import java.util.Base64;

public class ScopeHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public ScopeHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/scope/{url}", this::getScope);
        server.post("/scope", this::addScope);
        server.delete("/scope/{url}", this::deleteScope);
    }

    @OpenApi(
        summary = "Check if a URL is in scope",
        operationId = "getScope",
        path = "/scope/{url}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL to check", required = true)},
        responses = {
            @OpenApiResponse(status = "200", description = "URL scope check result", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", description = "Invalid URL", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void getScope(Context ctx) {
        String urlParam = ctx.pathParam("url") != null ? ctx.pathParam("url") : "";
        String plainURL;
        try {
            plainURL = new String(Base64.getDecoder().decode(urlParam));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", "Invalid Base64-encoded URL"));
            return;
        }

        try {
            URL url = URI.create(plainURL).toURL();
            ctx.status(200);
            ctx.json(new ApiResponse("is_in_scope", pwnService.isInScope(url)));
        } catch (MalformedURLException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", e.getMessage() != null ? e.getMessage() : "invalid url"));
        }
    }

    @OpenApi(
            summary = "Add a URL to scope",
            operationId = "addScope",
            path = "/scope",
            methods = {HttpMethod.POST},
            requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = URLMessage.class)}),
            responses = {
                    @OpenApiResponse(status = "201", description = "URL added to scope", content = {@OpenApiContent(from = URLMessage.class)}),
                    @OpenApiResponse(status = "400", description = "Invalid URL", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void addScope(Context ctx) {
        URLMessage scopeMSG = gson.fromJson(ctx.body(), URLMessage.class);
        try {
            URL url = URI.create(scopeMSG.url).toURL(); // Fix deprecated URL constructor (line 69)
            pwnService.includeInScope(url);
            ctx.status(201);
            ctx.json(scopeMSG);
        } catch (MalformedURLException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", e.getMessage() != null ? e.getMessage() : "invalid url"));
        }
    }

    @OpenApi(
            summary = "Remove a URL from scope",
            operationId = "deleteScope",
            path = "/scope/{url}",
            methods = {HttpMethod.DELETE},
            pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL to remove", required = true)},
            responses = {
                    @OpenApiResponse(status = "204", description = "URL removed from scope"),
                    @OpenApiResponse(status = "400", description = "Invalid URL", content = {@OpenApiContent(from = ApiResponse.class)})
            }
    )
    private void deleteScope(Context ctx) {
        String urlParam = ctx.pathParam("url") != null ? ctx.pathParam("url") : "";
        String plainURL;
        try {
            plainURL = new String(Base64.getDecoder().decode(urlParam));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", "Invalid Base64-encoded URL"));
            return;
        }

        try {
            URL url = URI.create(plainURL).toURL(); // Fix deprecated URL constructor (line 93)
            pwnService.excludeFromScope(url);
            ctx.status(204);
            ctx.result("");
        } catch (MalformedURLException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", e.getMessage() != null ? e.getMessage() : "invalid url"));
        }
    }
}
