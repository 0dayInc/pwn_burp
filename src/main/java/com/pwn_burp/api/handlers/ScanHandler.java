package com.pwn_burp.api.handlers;

import com.google.gson.*;
import com.pwn_burp.burp.*;
import com.pwn_burp.api.models.*;
import io.javalin.Javalin;
import io.javalin.http.*;
import io.javalin.openapi.*;
import java.net.*;
import java.util.Base64;

public class ScanHandler {
    private final PwnService pwnService;
    private final Gson gson = new Gson();

    public ScanHandler(PwnService pwnService) {
        this.pwnService = pwnService;
    }

    public void register(Javalin server) {
        server.get("/scanissues", this::getAllScanIssues);
        server.get("/scanissues/{url}", this::getScanIssuesByUrl);
        server.post("/scanissues", this::addScanIssue);
        server.post("/scan/active", this::startActiveScan);
        server.get("/scan/active", this::getActiveScanStatus);
        server.get("/scan/active/{id}", this::getActiveScanById);
        server.delete("/scan/active/{id}", this::cancelActiveScan);
        server.post("/scan/passive", this::startPassiveScan);
        server.get("/scanreport/{type}/{report_url}", this::generateScanReport);
        server.post("/spider", this::startSpider);
        server.get("/spider", this::getSpiderStatus);
        server.get("/spider/{id}", this::getSpiderById);
        server.delete("/spider/{id}", this::cancelSpider);
    }

    @OpenApi(
        summary = "Get all scan issues",
        operationId = "getAllScanIssues",
        path = "/scanissues",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(status = "200", description = "List of scan issues", content = {@OpenApiContent(type = "application/json")})
        }
    )
    private void getAllScanIssues(Context ctx) {
        ctx.status(200);
        ctx.json(pwnService.scanIssuesToJsonArray(pwnService.getScanIssues("")));
    }

    @OpenApi(
        summary = "Get scan issues for a specific URL",
        operationId = "getScanIssuesByUrl",
        path = "/scanissues/{url}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "url", description = "Base64-encoded URL", required = true)},
        responses = {
            @OpenApiResponse(status = "200", description = "List of scan issues", content = {@OpenApiContent(type = "application/json")})
        }
    )
    private void getScanIssuesByUrl(Context ctx) {
        String encodedUrl = ctx.pathParam("url") != null ? ctx.pathParam("url") : "";
        String url;
        try {
            url = new String(Base64.getDecoder().decode(encodedUrl));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("url", "Invalid Base64-encoded URL"));
            return;
        }

        ctx.status(200);
        ctx.json(pwnService.scanIssuesToJsonArray(pwnService.getScanIssues(url)));
    }

    @OpenApi(
        summary = "Add a custom scan issue (not supported)",
        operationId = "addScanIssue",
        path = "/scanissues",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ScanIssue.class)}),
        responses = {
            @OpenApiResponse(status = "201", description = "Scan issue added", content = {@OpenApiContent(from = ScanIssue.class)}),
            @OpenApiResponse(status = "400", description = "Invalid request", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void addScanIssue(Context ctx) {
        ScanIssue issue = gson.fromJson(ctx.body(), ScanIssue.class);
        pwnService.addScanIssue(issue);
        ctx.status(201);
        ctx.json(issue);
    }

    @OpenApi(
        summary = "Start an active scan",
        operationId = "startActiveScan",
        path = "/scan/active",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ScanMessage.class)}),
        responses = {
            @OpenApiResponse(status = "201", description = "Scan started", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "400", description = "Invalid request", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )

    private void startActiveScan(Context ctx) {
        try {
            ScanMessage scanMSG = gson.fromJson(ctx.body(), ScanMessage.class);
            if (scanMSG.host == null || scanMSG.request == null) {
                throw new IllegalArgumentException("Missing required fields: host or request");
            }
            byte[] request;
            try {
                request = Base64.getDecoder().decode(scanMSG.request);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid Base64-encoded request: " + e.getMessage());
            }
            int id = pwnService.doActiveScan(scanMSG.host, scanMSG.port, scanMSG.useHttps, request);
            ctx.status(201);
            ctx.json(new ApiResponse("id", id));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("error", e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Get status of all active scans",
        operationId = "getActiveScanStatus",
        path = "/scan/active",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(status = "200", description = "List of active scans", content = {@OpenApiContent(type = "application/json")})
        }
    )
    private void getActiveScanStatus(Context ctx) {
        ctx.status(200);
        respondWithJsonString(ctx, pwnService.getActiveScanStatus());
    }

    @OpenApi(
        summary = "Get status of a specific active scan",
        operationId = "getActiveScanById",
        path = "/scan/active/{id}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "id", description = "Scan ID", required = true, type = Integer.class)},
        responses = {
            @OpenApiResponse(status = "200", description = "Scan status", content = {@OpenApiContent(type = "application/json")}),
            @OpenApiResponse(status = "404", description = "Scan not found", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void getActiveScanById(Context ctx) {
        try {
            int id = Integer.parseInt(ctx.pathParam("id"));
            String result = pwnService.getActiveScanById(id);
            if (result == null || result.contains("\"status\":\"not_found\"")) {
                ctx.status(404);
                ctx.json(pwnService.apiError("id", "scan item not found"));
            } else {
                ctx.status(200);
                respondWithJsonString(ctx, result);
            }
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid scan ID format"));
        } catch (Exception e) {
            // NEW: Handle unexpected errors, including potential API issues
            pwnService.getLogging().logToError("Error fetching scan status for ID " + ctx.pathParam("id") + ": " + e.getMessage());
            ctx.status(500);
            ctx.json(pwnService.apiError("error", "Failed to fetch scan status: " + e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Cancel an active scan",
        operationId = "cancelActiveScan",
        path = "/scan/active/{id}",
        methods = {HttpMethod.DELETE},
        pathParams = {@OpenApiParam(name = "id", description = "Scan ID", required = true, type = Integer.class)},
        responses = {
            @OpenApiResponse(status = "204", description = "Scan cancelled"),
            @OpenApiResponse(status = "404", description = "Scan not found", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void cancelActiveScan(Context ctx) {
        try {
            int id = Integer.parseInt(ctx.pathParam("id"));
            boolean cancelled = pwnService.cancelActiveScan(id);
            if (!cancelled) {
                ctx.status(404);
                ctx.json(pwnService.apiError("id", "scan item not found"));
            } else {
                ctx.status(204);
                ctx.result("");
            }
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid scan ID format"));
        }
    }

    @OpenApi(
        summary = "Start a passive scan",
        operationId = "startPassiveScan",
        path = "/scan/passive",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = ScanMessage.class)}),
        responses = {
            @OpenApiResponse(status = "201", description = "Passive scan started")
        }
    )
    private void startPassiveScan(Context ctx) {
        try {
            ScanMessage scanMSG = gson.fromJson(ctx.body(), ScanMessage.class);
            if (scanMSG.host == null || scanMSG.request == null) {
                throw new IllegalArgumentException("Missing required fields: host or request");
            }
            byte[] request;
            byte[] response;
            try {
                request = Base64.getDecoder().decode(scanMSG.request);
                response = Base64.getDecoder().decode(scanMSG.response);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid Base64-encoded request or response: " + e.getMessage());
            }
            pwnService.doPassiveScan(scanMSG.host, scanMSG.port, scanMSG.useHttps, request, response);
            ctx.status(201);
            ctx.json(new ApiResponse("passive_scan", "running..."));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("error", e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Generate a scan report in HTML or XML format",
        operationId = "generateScanReport",
        path = "/scanreport/{type}/{report_url}",
        methods = {HttpMethod.GET},
        pathParams = {
            @OpenApiParam(name = "type", description = "Report type (HTML or XML)", required = true, type = String.class),
            @OpenApiParam(name = "report_url", description = "Base64-encoded target URL", required = true, type = String.class)
        },
        responses = {
            @OpenApiResponse(
                status = "200",
                description = "Scan report content (text/html if type=HTML, application/xml if type=XML)",
                content = {
                    @OpenApiContent(type = "text/html"),
                    @OpenApiContent(type = "application/xml")
                }
            ),
            @OpenApiResponse(status = "400", description = "Invalid request or no issues found", content = {@OpenApiContent(from = ApiResponse.class)}),
            @OpenApiResponse(status = "500", description = "Report generation failed", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void generateScanReport(Context ctx) {
        try {
            String reportType = ctx.pathParam("type").toUpperCase();
            String reportUrl = ctx.pathParam("report_url");
            if (reportUrl == null || reportUrl.isEmpty()) {
                pwnService.getLogging().logToError("Missing required parameter: report_url");
                throw new IllegalArgumentException("Missing required parameter: report_url");
            }
            String decodedUrl;
            try {
                decodedUrl = new String(Base64.getDecoder().decode(reportUrl));
            } catch (IllegalArgumentException e) {
                pwnService.getLogging().logToError("Invalid Base64 encoding for report_url: " + reportUrl);
                throw new IllegalArgumentException("Invalid Base64 encoding for report_url");
            }
            String host;
            try {
                host = new URI(decodedUrl).getHost();
                if (host == null) {
                    pwnService.getLogging().logToError("Invalid target URL: unable to extract host from " + decodedUrl);
                    throw new IllegalArgumentException("Invalid target URL: unable to extract host");
                }
            } catch (URISyntaxException e) {
                pwnService.getLogging().logToError("Invalid URI syntax for decoded URL: " + decodedUrl);
                throw new IllegalArgumentException("Invalid URI syntax for decoded URL: " + e.getMessage());
            }
            // NEW: Log the decoded URL and host for debugging
            pwnService.getLogging().logToOutput("Generating report for URL: " + decodedUrl + ", host: " + host);
            String reportContent = pwnService.generateScanReport(host, reportType);
            if (reportContent.startsWith("{\"error\":")) {
                pwnService.getLogging().logToError("Report generation error: " + reportContent);
                ctx.status(400);
                ctx.json(gson.fromJson(reportContent, ApiResponse.class));
            } else {
                ctx.status(200);
                ctx.contentType(reportType.equalsIgnoreCase("HTML") ? "text/html" : "application/xml");
                ctx.result(reportContent);
            }
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("error", e.getMessage()));
        } catch (Exception e) {
            pwnService.getLogging().logToError("Unexpected error in generateScanReport: " + e.getMessage());
            ctx.status(500);
            ctx.json(pwnService.apiError("error", "Report generation failed: " + e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Start spidering (crawling) a target URL",
        operationId = "startSpider",
        path = "/spider",
        methods = {HttpMethod.POST},
        requestBody = @OpenApiRequestBody(content = {@OpenApiContent(from = URLMessage.class)}),
        responses = {
            @OpenApiResponse(status = "201", description = "Spidering started", content = {@OpenApiContent(from = SpiderResponse.class)}),
            @OpenApiResponse(status = "400", description = "Invalid request", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void startSpider(Context ctx) {
        try {
            URLMessage urlMsg = gson.fromJson(ctx.body(), URLMessage.class);
            if (urlMsg == null || urlMsg.url == null || urlMsg.url.isEmpty()) {
                throw new IllegalArgumentException("Missing or invalid 'url' field in request body");
            }
            try {
                URI.create(urlMsg.url).toURL(); // Validate URL
            } catch (IllegalArgumentException | MalformedURLException e) {
                throw new IllegalArgumentException("Invalid URL format: " + e.getMessage());
            }
            int id = pwnService.doCrawl(urlMsg.url);
            if (id == -1) {
                throw new IllegalArgumentException("Target out of scope");
            }
            pwnService.getLogging().logToOutput("Spidering started for URL: " + urlMsg.url + " with ID: " + id);
            ctx.status(201);
            ctx.json(new SpiderResponse(id));
        } catch (IllegalArgumentException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("error", e.getMessage()));
        } catch (Exception e) {
            pwnService.getLogging().logToError("Unexpected error starting spider: " + e.getMessage());
            ctx.status(500);
            ctx.json(pwnService.apiError("error", "Failed to start spider: " + e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Get status of all spider tasks",
        operationId = "getSpiderStatus",
        path = "/spider",
        methods = {HttpMethod.GET},
        responses = {
            @OpenApiResponse(status = "200", description = "List of spider tasks", content = {@OpenApiContent(type = "application/json")})
        }
    )
    private void getSpiderStatus(Context ctx) {
        ctx.status(200);
        respondWithJsonString(ctx, pwnService.getCrawlStatus());
    }

    @OpenApi(
        summary = "Get status of a specific spider task",
        operationId = "getSpiderById",
        path = "/spider/{id}",
        methods = {HttpMethod.GET},
        pathParams = {@OpenApiParam(name = "id", description = "Spider ID", required = true, type = Integer.class)},
        responses = {
            @OpenApiResponse(status = "200", description = "Spider status", content = {@OpenApiContent(type = "application/json")}),
            @OpenApiResponse(status = "404", description = "Spider not found", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void getSpiderById(Context ctx) {
        try {
            int id = Integer.parseInt(ctx.pathParam("id"));
            String result = pwnService.getCrawlById(id);
            if (result.contains("\"status\":\"not_found\"")) {
                ctx.status(404);
                ctx.json(pwnService.apiError("id", "spider item not found"));
            } else {
                ctx.status(200);
                respondWithJsonString(ctx, result);
            }
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid spider ID format"));
        } catch (Exception e) {
            pwnService.getLogging().logToError("Error fetching spider status for ID " + ctx.pathParam("id") + ": " + e.getMessage());
            ctx.status(500);
            ctx.json(pwnService.apiError("error", "Failed to fetch spider status: " + e.getMessage()));
        }
    }

    @OpenApi(
        summary = "Cancel a spider task",
        operationId = "cancelSpider",
        path = "/spider/{id}",
        methods = {HttpMethod.DELETE},
        pathParams = {@OpenApiParam(name = "id", description = "Spider ID", required = true, type = Integer.class)},
        responses = {
            @OpenApiResponse(status = "204", description = "Spider cancelled"),
            @OpenApiResponse(status = "404", description = "Spider not found", content = {@OpenApiContent(from = ApiResponse.class)})
        }
    )
    private void cancelSpider(Context ctx) {
        try {
            int id = Integer.parseInt(ctx.pathParam("id"));
            boolean cancelled = pwnService.cancelCrawl(id);
            if (!cancelled) {
                ctx.status(404);
                ctx.json(pwnService.apiError("id", "spider item not found"));
            } else {
                ctx.status(204);
                ctx.result("");
            }
        } catch (NumberFormatException e) {
            ctx.status(400);
            ctx.json(pwnService.apiError("id", "Invalid spider ID format"));
        }
    }

    private void respondWithJsonString(Context ctx, String json) {
        ctx.contentType("application/json");
        ctx.result(json == null ? "{}" : json);
    }
}
