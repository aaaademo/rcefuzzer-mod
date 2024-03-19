package modules;

import burp.*;
import commmon.CommonUtils;
import commmon.Tweb;
import commmon.YamlTools;
import core.Config;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class SsrfPollution {
  private final List<String> headers;
  
  private static String host = null;
  
  private static URL url;
  
  private final IHttpService iHttpService;
  
  public SsrfPollution(IHttpRequestResponse baseRequestResponse) {
    this.headers = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getHeaders();
    url = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getUrl();
    this.iHttpService = baseRequestResponse.getHttpService();
    host = this.iHttpService.getHost();
    List<IScanIssue> issues = new ArrayList<>();
    byte[] request = baseRequestResponse.getRequest();
    IHttpService service = baseRequestResponse.getHttpService();
    IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(request);
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    String status = ((HashMap)yaml.getValueByKey("ssrfPollution", new HashMap<>())).get("status").toString();
    if (status.equals("true")) {
      if (reqInfo.getMethod().equals("GET")) {
        RunTestOnParameters("GET", issues, reqInfo, baseRequestResponse, request, service, (byte)0);
        RunTestOnXForwardedHost("GET", issues, reqInfo, baseRequestResponse, service);
        RunTestOnHostHeader("GET", issues, reqInfo, baseRequestResponse, service);
        RunTestInUserAgent("GET", issues, reqInfo, baseRequestResponse, service);
        RunTestInPath("GET", issues, reqInfo, baseRequestResponse, service);
        RunTestInReferer("GET", issues, reqInfo, baseRequestResponse, service);
      } 
      if (reqInfo.getMethod().equals("POST")) {
        RunTestOnParameters("POST", issues, reqInfo, baseRequestResponse, request, service, (byte)1);
        RunTestOnXForwardedHost("POST", issues, reqInfo, baseRequestResponse, service);
        RunTestOnHostHeader("POST", issues, reqInfo, baseRequestResponse, service);
        RunTestInUserAgent("POST", issues, reqInfo, baseRequestResponse, service);
        RunTestInPath("POST", issues, reqInfo, baseRequestResponse, service);
        RunTestInReferer("POST", issues, reqInfo, baseRequestResponse, service);
      } 
    } 
  }
  
  public void RunTestOnParameters(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, byte[] request, IHttpService service, byte paramType) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    List<IParameter> params = reqInfo.getParameters();
    for (int i = 0; i < params.size(); i++) {
      IParameter param = params.get(i);
      IParameter newParam = BurpExtender.helpers.buildParameter(param.getName(), "http://" + payload, paramType);
      if (param.getType() != 2 && !param.getName().contains("_csrf")) {
        request = BurpExtender.helpers.updateParameter(request, newParam);
        IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
        String dnsresp = (new Tweb()).getlog(key, Boolean.valueOf(true));
        if (!dnsresp.isEmpty()) {
          BurpExtender.stdout.println("Found SSRF");
          BurpExtender.stdout.println("Host: " + host);
          BurpExtender.stdout.println("Path: " + path);
          BurpExtender.stdout.println("Method: " + method);
          String title = "Parameter Based SSRF";
          String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Parameter</b>\n";
          CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
          issues.add(issue);
          BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
        } 
      } 
    } 
  }
  
  public void RunTestOnXForwardedHost(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    List<String> headers = reqInfo.getHeaders();
    headers.add("X-Forwarded-Host: " + payload);
    byte[] request = BurpExtender.helpers.buildHttpMessage(headers, null);
    IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
    String dnsresp = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "X-Forwarded-Host Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>X-Forwarded-Host</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
  }
  
  public void RunTestOnHostHeader(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    List<String> headers = reqInfo.getHeaders();
    headers.set(1, "Host: " + payload);
    byte[] request = BurpExtender.helpers.buildHttpMessage(headers, null);
    IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
    String dnsresp = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "Host Header Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Host Header</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
    String key2 = CommonUtils.getRandomString(6);
    String payload2 = String.format("%s.%s.ssrf.%s", new Object[] { key2, host, (new Tweb()).getDomain() });
    String[] hostValue = host.split(" ");
    List<String> headers2 = reqInfo.getHeaders();
    headers2.set(1, "Host: " + hostValue[1] + "@" + payload2);
    byte[] request2 = BurpExtender.helpers.buildHttpMessage(headers2, null);
    IHttpRequestResponse resp2 = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request2);
    String dnsresp2 = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp2.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "Host Header Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Host Header</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp2 }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
  }
  
  public void RunTestInUserAgent(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    boolean foundHeader = false;
    List<String> headers = reqInfo.getHeaders();
    for (int i = 0; i < headers.size(); i++) {
      if (((String)headers.get(i)).contains("User-Agent")) {
        headers.set(i, "User-Agent: " + payload);
        foundHeader = true;
        break;
      } 
    } 
    if (!foundHeader)
      headers.add("User-Agent: " + payload); 
    byte[] request = BurpExtender.helpers.buildHttpMessage(headers, null);
    IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
    String dnsresp2 = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp2.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "User-Agent Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>User-Agent</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
  }
  
  public void RunTestInReferer(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    boolean foundHeader = false;
    List<String> headers = reqInfo.getHeaders();
    for (int i = 0; i < headers.size(); i++) {
      if (((String)headers.get(i)).contains("Referer")) {
        headers.set(i, "Referer: http://" + payload);
        foundHeader = true;
        break;
      } 
    } 
    if (!foundHeader)
      headers.add("Referer: http://" + payload); 
    byte[] request = BurpExtender.helpers.buildHttpMessage(headers, null);
    IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
    String dnsresp2 = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp2.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "Referer Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Referer</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
  }
  
  public void RunTestInPath(String method, List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    String key = CommonUtils.getRandomString(6);
    String payload = String.format("%s.%s.ssrf.%s", new Object[] { key, SsrfPollution.host, (new Tweb()).getDomain() });
    URL url = BurpExtender.helpers.analyzeRequest(content).getUrl();
    String path = reqInfo.getHeaders().get(0);
    String host = reqInfo.getHeaders().get(1);
    List<String> headers1 = reqInfo.getHeaders();
    List<String> headers2 = reqInfo.getHeaders();
    String[] pathParts1 = path.split(" ");
    String newPath1 = method + " @" + payload + pathParts1[1] + " HTTP/1.1";
    headers1.set(0, newPath1);
    byte[] request1 = BurpExtender.helpers.buildHttpMessage(headers1, null);
    IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request1);
    String[] pathParts2 = path.split(" ");
    String newPath2 = method + " http://" + payload + pathParts2[1] + " HTTP/1.1";
    headers2.set(0, newPath2);
    byte[] request = BurpExtender.helpers.buildHttpMessage(headers2, null);
    resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request);
    String dnsresp2 = (new Tweb()).getlog(key, Boolean.valueOf(true));
    if (!dnsresp2.isEmpty()) {
      BurpExtender.stdout.println("Found SSRF");
      BurpExtender.stdout.println("Host: " + host);
      BurpExtender.stdout.println("Path: " + path);
      BurpExtender.stdout.println("Method: " + method);
      String title = "Path Based SSRF";
      String message = "<br>Method: <b>" + method + "\n</b><br>EndPoint: <b>" + path + "\n</b><br>\nLocation: <b>Path</b>\n";
      CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[] { resp }, title, message, "High");
      issues.add(issue);
      BurpExtender.callbacks.addScanIssue((IScanIssue)issue);
    } 
  }
}
