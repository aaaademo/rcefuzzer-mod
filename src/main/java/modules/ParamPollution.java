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
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

public class ParamPollution {
  public URL url;
  public IHttpRequestResponse iHttpRequestResponse;
  public IHttpService iHttpService;
  private static String host = null;
  public ArrayList<String> exprPayloads = new ArrayList();
  public ArrayList<String> cmdPayloads = new ArrayList();
  public ArrayList<String> pythonPayloads = new ArrayList();

  public ParamPollution(IHttpRequestResponse baseRequestResponse) {
    this.iHttpRequestResponse = baseRequestResponse;
    this.iHttpService = baseRequestResponse.getHttpService();
    this.url = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getUrl();
    host = this.iHttpService.getHost();
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    String[] var3 = ((HashMap)yaml.getValueByKey("paramPollution", new HashMap())).get("exprs").toString().split("\n");
    int var4 = var3.length;

    int var5;
    String payload;
    for(var5 = 0; var5 < var4; ++var5) {
      payload = var3[var5];
      this.exprPayloads.add(payload);
    }

    var3 = ((HashMap)yaml.getValueByKey("paramPollution", new HashMap())).get("value").toString().split("\n");
    var4 = var3.length;

    for(var5 = 0; var5 < var4; ++var5) {
      payload = var3[var5];
      this.cmdPayloads.add(payload);
    }

    var3 = ((HashMap)yaml.getValueByKey("jsonPollution", new HashMap())).get("value").toString().split("\n");
    var4 = var3.length;

    for(var5 = 0; var5 < var4; ++var5) {
      payload = var3[var5];
      this.pythonPayloads.add(payload);
    }

    String status = ((HashMap)yaml.getValueByKey("paramPollution", new HashMap())).get("status").toString().trim();
    if (status.equals("true")) {
      List<IParameter> parameters = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getParameters();
      Iterator var9 = parameters.iterator();

      while(var9.hasNext()) {
        IParameter parameter = (IParameter)var9.next();
        if (parameter.getType() < 2) {
          this.codeEval(parameter, parameter.getType());
          this.commandExecute(parameter, parameter.getType());
          this.jsonEval(parameter, parameter.getValue(), parameter.getType());
        }
      }
    }

  }

  public void jsonEval(final IParameter parameter, final String paramValue, final int method) {
    Iterator var4 = this.pythonPayloads.iterator();

    while(var4.hasNext()) {
      final String payload = (String)var4.next();
      Thread thread = new Thread(new Runnable() {
        public void run() {
          String key = CommonUtils.getRandomString(6);
          String dnslog = String.format("%s.%s.jsoneval.%s", key, ParamPollution.host, (new Tweb()).getDomain());
          String tmp = payload.replaceAll("dnslog", dnslog).trim().replaceAll("\r|\n", "");
          String res = CommonUtils.jsonPollution(paramValue, tmp);
          if (!res.equals(paramValue)) {
            try {
              IParameter newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), res, (byte)method);
              if (StringUtils.isAsciiPrintable(parameter.getValue())) {
                BurpExtender.stdout.println(String.format("param: %s \toldValue: %s \tnewValue: %s \ttype: %s", parameter.getName(), parameter.getValue(), newParameter.getValue(), parameter.getType()));
              }

              byte[] newRequest = BurpExtender.helpers.updateParameter(ParamPollution.this.iHttpRequestResponse.getRequest(), newParameter);
              IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(ParamPollution.this.iHttpService, newRequest);

              try {
                Thread.sleep((long)Config.TIMEOUT);
              } catch (Exception var9) {
              }

              String dnsresp = (new Tweb()).getlog(key);
              if (!dnsresp.isEmpty()) {
                BurpExtender.callbacks.addScanIssue(new CustomScanIssue(ParamPollution.this.iHttpService, ParamPollution.this.url, new IHttpRequestResponse[]{resp}, "Python Eval Json", String.format("<strong>payload</strong>:<br>%s=%s<br><strong>tweb</strong>:<br>%s", newParameter.getName(), newParameter.getValue(), dnsresp), "High"));
              }
            } catch (Exception var10) {
              BurpExtender.stderr.println(var10.getMessage());
            }
          }

        }
      });
      thread.start();
    }

  }

  public void commandExecute(final IParameter parameter, final int method) {
    Iterator var3 = this.cmdPayloads.iterator();

    while(var3.hasNext()) {
      final String cmd = (String)var3.next();
      Thread thread = new Thread(new Runnable() {
        public void run() {
          String key = CommonUtils.getRandomString(6);
          String dnslog = String.format("%s.%s.cmd.%s", key, ParamPollution.host, (new Tweb()).getDomain());
          String payload = cmd.replaceAll("dnslog", dnslog).trim().replaceAll("\r|\n", "");

          try {
            IParameter newParameter = null;
            if (CommonUtils.isBase64(parameter.getValue())) {
              newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), new String(Base64.getEncoder().encode(payload.getBytes())), (byte)method);
            } else if (CommonUtils.isEscape(parameter.getValue())) {
              newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), StringEscapeUtils.escapeJava(payload), (byte)method);
            } else {
              newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), payload, (byte)method);
            }

            if (StringUtils.isAsciiPrintable(parameter.getValue())) {
              BurpExtender.stdout.println(String.format("param: %s \toldValue: %s \tnewValue: %s \ttype: %s", parameter.getName(), parameter.getValue(), newParameter.getValue(), parameter.getType()));
            }

            byte[] newRequest = BurpExtender.helpers.updateParameter(ParamPollution.this.iHttpRequestResponse.getRequest(), newParameter);
            IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(ParamPollution.this.iHttpService, newRequest);

            try {
              Thread.sleep((long)Config.TIMEOUT);
            } catch (Exception var8) {
            }

            String dnsresp = (new Tweb()).getlog(key);
            if (!dnsresp.isEmpty()) {
              BurpExtender.callbacks.addScanIssue(new CustomScanIssue(ParamPollution.this.iHttpService, ParamPollution.this.url, new IHttpRequestResponse[]{resp}, "Command Inject", String.format("<strong>payload</strong>:<br>%s=%s<br><strong>tweb</strong>:<br>%s", newParameter.getName(), newParameter.getValue(), dnsresp), "High"));
            }
          } catch (Exception var9) {
            BurpExtender.stderr.println(var9.getMessage());
          }

        }
      });
      thread.start();
    }

  }

  public void codeEval(IParameter parameter, int method) {
    Iterator var3 = this.exprPayloads.iterator();

    while(var3.hasNext()) {
      String temp = (String)var3.next();
      String expr = temp.split("\\|")[0];
      String expect = temp.split("\\|")[1];

      try {
        IParameter newParameter = null;
        if (CommonUtils.isBase64(parameter.getValue())) {
          newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), new String(Base64.getEncoder().encode(expr.getBytes())), (byte)method);
        } else if (CommonUtils.isEscape(parameter.getValue())) {
          newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), StringEscapeUtils.escapeJava(expr), (byte)method);
        } else {
          newParameter = BurpExtender.helpers.buildParameter(parameter.getName(), expr, (byte)method);
        }

        BurpExtender.stdout.println(String.format("param: %s \toldValue: %s \tnewValue: %s \ttype: %s", parameter.getName(), parameter.getValue(), newParameter.getValue(), parameter.getType()));
        byte[] newRequest = BurpExtender.helpers.updateParameter(this.iHttpRequestResponse.getRequest(), newParameter);
        IHttpRequestResponse resp = BurpExtender.callbacks.makeHttpRequest(this.iHttpService, newRequest);
        String body = new String(resp.getResponse());
        if (body.contains(expect)) {
          BurpExtender.callbacks.addScanIssue(new CustomScanIssue(this.iHttpService, this.url, new IHttpRequestResponse[]{resp}, "Code Expr Eval", String.format("%s=%s<br>", newParameter.getName(), newParameter.getValue()), "High"));
          BurpExtender.stdout.println("======================================================================================");
          BurpExtender.stdout.println("=====================================Code Eval Found==================================");
          BurpExtender.stdout.println("======================================================================================");
          BurpExtender.stdout.println(new String(newRequest));
          BurpExtender.stdout.println("--------------------------------------------------------------------------------------");
          BurpExtender.stdout.println(body);
          BurpExtender.stdout.println("======================================================================================\n");
        }
      } catch (Exception var11) {
        BurpExtender.stderr.println(var11.getMessage());
      }
    }

  }
}
