//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package modules;

import burp.*;
import commmon.CommonUtils;
import commmon.Tweb;
import commmon.YamlTools;
import core.Config;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class HeaderPollution {
  private final List<String> headers;
  private static String host = null;
  private static URL url;
  private final IHttpService iHttpService;
  public ArrayList<String> allinPayloads = new ArrayList();
  public ArrayList<String> headerPayloads = new ArrayList();

  public HeaderPollution(IHttpRequestResponse baseRequestResponse) {
    this.headers = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getHeaders();
    url = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getUrl();
    this.iHttpService = baseRequestResponse.getHttpService();
    host = this.iHttpService.getHost();
    List<IScanIssue> issues = new ArrayList();
    byte[] request = baseRequestResponse.getRequest();
    IHttpService service = baseRequestResponse.getHttpService();
    IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(request);
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    String status = ((HashMap)yaml.getValueByKey("headerPollution", new HashMap())).get("status").toString().trim();
    String[] var8 = ((HashMap)yaml.getValueByKey("headerPollution", new HashMap())).get("allin").toString().split("\n");
    int var9 = var8.length;

    int var10;
    String payload;
    for(var10 = 0; var10 < var9; ++var10) {
      payload = var8[var10];
      this.allinPayloads.add(payload.trim());
    }

    var8 = ((HashMap)yaml.getValueByKey("headerPollution", new HashMap())).get("headers").toString().split("\n");
    var9 = var8.length;

    for(var10 = 0; var10 < var9; ++var10) {
      payload = var8[var10];
      this.headerPayloads.add(payload.trim());
    }

    if (status.equals("true")) {
      this.headersInject(issues, reqInfo, baseRequestResponse, service);
      this.headersAdd(issues, reqInfo, baseRequestResponse, service);
    }

  }

  public void headersAdd(List<IScanIssue> issues, IRequestInfo reqInfo, IHttpRequestResponse content, IHttpService service) {
    byte[] request = content.getRequest();
    IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
    int bodyOffset = requestInfo.getBodyOffset();
    int body_length = request.length - bodyOffset;
    byte[] byteBody = new byte[body_length];
    System.arraycopy(request, bodyOffset, byteBody, 0, body_length);
    if (this.headerPayloads.size() > 0) {
      String dnskey = CommonUtils.getRandomString(6);
      String dnslog = String.format("%s.%s.headerpollution.%s", dnskey, host, (new Tweb()).getDomain());
      List<String> headers = reqInfo.getHeaders();
      Iterator var13 = this.headerPayloads.iterator();

      String dnsresp2;
      String title;
      while(var13.hasNext()) {
        Object headerPayload = var13.next();
        dnsresp2 = headerPayload.toString().split("\\|")[0];
        title = headerPayload.toString().split("\\|")[1];
        boolean isExist = false;
        int n = 0;

        for(int i = 2; i < headers.size(); ++i) {
          if (((String)headers.get(i)).contains(dnsresp2)) {
            isExist = true;
            n = i;
          }
        }

        if (isExist) {
          headers.set(n, String.format("%s%s", headers.get(n), title.replaceAll("dnslog", dnslog)));
        } else {
          headers.add(String.format("%s: %s", dnsresp2, title.replaceAll("dnslog", dnslog)));
        }
      }

      byte[] request2 = BurpExtender.helpers.buildHttpMessage(headers, byteBody);
      IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request2);

      try {
        Thread.sleep((long)Config.TIMEOUT);
      } catch (Exception var20) {
      }

      dnsresp2 = (new Tweb()).getlog(dnskey);
      if (!dnsresp2.isEmpty()) {
        BurpExtender.stdout.println("Found RCE");
        BurpExtender.stdout.println("Host: " + host);
        title = "Header Inject";
        String message = "<br>DNSLOG: <b>" + dnsresp2;
        CustomScanIssue issue = new CustomScanIssue(service, url, new IHttpRequestResponse[]{resp}, title, message, "High");
        issues.add(issue);
        BurpExtender.callbacks.addScanIssue(issue);
      }
    }

  }

  public void headersInject(final List<IScanIssue> issues, final IRequestInfo reqInfo, final IHttpRequestResponse content, final IHttpService service) {
    byte[] request = content.getRequest();
    IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
    int bodyOffset = requestInfo.getBodyOffset();
    int body_length = request.length - bodyOffset;
    final byte[] byteBody = new byte[body_length];
    System.arraycopy(request, bodyOffset, byteBody, 0, body_length);
    if (this.allinPayloads.size() > 0) {
      Iterator var10 = this.allinPayloads.iterator();

      while(var10.hasNext()) {
        final Object headerPayload = var10.next();
        (new Thread(new Runnable() {
          public void run() {
            List<String> headers = reqInfo.getHeaders();
            String key = CommonUtils.getRandomString(6);
            String dnslog = String.format("%s.%s.headerpollution.%s", key, HeaderPollution.host, (new Tweb()).getDomain());

            for(int i = 2; i < headers.size(); ++i) {
              if (!((String)headers.get(i)).contains("Content-Type")) {
                headers.set(i, String.format("%s%s", headers.get(i), headerPayload.toString().replaceAll("dnslog", dnslog)));
              }
            }

            byte[] request2 = BurpExtender.helpers.buildHttpMessage(headers, byteBody);
            IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(content.getHttpService(), request2);

            try {
              Thread.sleep((long)Config.TIMEOUT);
            } catch (Exception var10) {
            }

            String dnsresp2 = (new Tweb()).getlog(key);
            if (!dnsresp2.isEmpty()) {
              BurpExtender.stdout.println("Found RCE");
              BurpExtender.stdout.println("Host: " + HeaderPollution.host);
              String title = "Header Inject";
              String message = "<br>DNSLOG: <b>" + dnsresp2;
              CustomScanIssue issue = new CustomScanIssue(service, HeaderPollution.url, new IHttpRequestResponse[]{resp}, title, message, "High");
              issues.add(issue);
              BurpExtender.callbacks.addScanIssue(issue);
            }

          }
        })).start();
      }
    }

  }
}
