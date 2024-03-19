package commmon;

import burp.BurpExtender;
import core.Config;
import java.util.HashMap;
import java.util.Map;


public class Tweb {
  public static String apiKey;

  public static String domain;
  public static String dnslogType;
  public static String subDomain;

  public Tweb() {
//    YamlTools yaml = new YamlTools(Config.YAML_PATH);
//    setType(((HashMap)yaml.<HashMap>getValueByKey("config", new HashMap<>())).get("dnslogType").toString().trim());
//    setBasaeDomain(((HashMap)yaml.<HashMap>getValueByKey("config", new HashMap<>())).get("dnslogDomain").toString().trim());
//    setApi(((HashMap)yaml.<HashMap>getValueByKey("config", new HashMap<>())).get("dnslogApiKey").toString().trim());

    setType(getType());

    setBasaeDomain(getBasaeDomain());

    setSubDomain(getSubDomain());

    setApiKey(getApiKey());



  }
  public static String getType() {
    return dnslogType;
  }

  public static void setType(String Type) {
    Tweb.dnslogType = Type;
  }

  public static String getDomain() {
    return subDomain;
  }
  public static void setBasaeDomain(String domain) {
    Tweb.domain = domain;
  }
  public static String getBasaeDomain() {
    return domain;
  }

  public static void setDomain(String domain) {
    Tweb.domain = domain;
  }

  public static String getSubDomain() {
    return subDomain;
  }
  public static void setSubDomain(String sub) {
    Tweb.subDomain = sub;
  }
  public void setSubDomainAndApi(String sub) {
    DnslogUtils.CallbackRedPT.getDomainAndApi(domain);
    Tweb.subDomain = sub;
  }

  public static String getApiKey() {
    return apiKey;
  }
  
  public static void setApiKey(String key) {
    Tweb.apiKey = key;
  }

  public static void initSubDomainAndApi(){
    YamlTools yaml = new YamlTools(Config.YAML_PATH);
    setType(((HashMap)yaml.<HashMap>getValueByKey("config", new HashMap<>())).get("dnslogType").toString().trim());

    if (dnslogType.contains("callback")) {
      setBasaeDomain(((HashMap)yaml.<HashMap>getValueByKey("config", new HashMap<>())).get("dnslogDomain").toString().trim());
      Map<String, Object> res = DnslogUtils.CallbackRedPT.getDomainAndApi("callback.red");
      String subdomain1 = (String) res.get("subdomain");
      String apikey1 = (String) res.get("key");
      setSubDomain(subdomain1);
      setApiKey(apikey1);
      BurpExtender.stdout.println(String.format("subdomain: %s\nkey: %s", subdomain1,apikey1));
    }

  }
  
  public String getlog(String key, Boolean isSSRF) {

    return getlog(key);
  }
  
  public String getlog(String randomKey) {
//    BurpExtender.stdout.println("domain: "+ domain +"\n" +"domain: "+ subDomain +"\n" + "apikey: "+ apiKey + "\n");

    if (dnslogType.contains("callback")) {
      // TODO: 添加 randomkey 随机前缀 内容判断
      return DnslogUtils.CallbackRedPT.getLog(domain,apiKey,randomKey);
    } else if (dnslogType.contains("ceye")) {
      return "";
    } else if (dnslogType.contains("burp")) {
      return "";
    } else if (dnslogType.contains("dnslogcn")) {
      return "";
    }
    return "";
  }
  
  public static void main(String[] args) throws InterruptedException {
    String key = CommonUtils.getRandomString(4);
    Map<String, Object> res = DnslogUtils.CallbackRedPT.getDomainAndApi("callback.red");
    String subdomain1 = (String) res.get("subdomain");
    String apikey1 = (String) res.get("key");
    System.out.println(String.format("subdomain: %s\nkey: %s", subdomain1,apikey1));

    Thread.sleep(20000L);
//    String res = (new Tweb()).getlog(key);

//    System.out.println("res:" + res);
    DnslogUtils.CallbackRedPT.getLog("callback.red",apikey1);
  }
}
