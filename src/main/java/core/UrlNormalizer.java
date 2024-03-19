package core;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;

import java.util.List;
import java.util.regex.Pattern;

public class UrlNormalizer {
  public static boolean isNotRepeat(IHttpRequestResponse baseRequestResponse) {
    String method = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getMethod();
    String protocol = baseRequestResponse.getHttpService().getProtocol();
    String host = baseRequestResponse.getHttpService().getHost();
    String port = String.valueOf(baseRequestResponse.getHttpService().getPort());
    String fullUrl = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getUrl().toString();
    fullUrl = (fullUrl.indexOf("?") > 0) ? fullUrl.substring(0, fullUrl.indexOf("?")) : fullUrl;
    String urlpath = normalize(fullUrl.replace(String.format("%s://%s:%s", new Object[] { protocol, host, port }), ""));
    String parameterStrs = "";
    List<IParameter> parameters = BurpExtender.helpers.analyzeRequest(baseRequestResponse).getParameters();
    for (IParameter parameter : parameters)
      parameterStrs = parameterStrs + parameter.getName(); 
    String normalizeData = String.format("%s:%s:%s:%s:%s:%s", new Object[] { method, protocol, host, port, urlpath, parameterStrs });
    if (!FakeRedis.isInCache(normalizeData)) {
      FakeRedis.addToCache(normalizeData);
      BurpExtender.stdout.println(String.format("cache data: %s\tisNotRepeat:%s", new Object[] { normalizeData, Boolean.valueOf(true) }));
      return true;
    } 
    BurpExtender.stdout.println(String.format("cache data: %s\tisNotRepeat:%s", new Object[] { normalizeData, Boolean.valueOf(false) }));
    return false;
  }
  
  public static String normalize(String fullUrl) {
    while (fullUrl.contains("//"))
      fullUrl = fullUrl.replaceAll("//", "/"); 
    return removeInt(fullUrl);
  }
  
  public static boolean toInt(String urlPath) {
    try {
      Integer.parseInt(urlPath);
      return true;
    } catch (Exception e) {
      return false;
    } 
  }
  
  public static boolean isHash(String urlPath) {
    String md5_max = "^[0-9A-Za-z]{32}$";
    String md5_min = "^[0-9A-Za-z]{16}$";
    String unKnow = "^[0-9A-Za-z]{8}$";
    String uuid = "\\w{8}(-\\w{4}){3}-\\w{12}";
    return Pattern.matches(uuid, urlPath) | 
      Pattern.matches(md5_max, urlPath) | 
      Pattern.matches(md5_min, urlPath) | 
      Pattern.matches(unKnow, urlPath);
  }
  
  public static String removeInt(String fullUrl) {
    String[] urlPaths = fullUrl.split("/");
    int pos = 0;
    for (String urlPath : urlPaths) {
      pos++;
      isHash(urlPath);
      if (!urlPath.isEmpty() && toInt(urlPath))
        urlPaths[pos - 1] = "{ID}"; 
      if (!urlPath.isEmpty() && isHash(urlPath))
        urlPaths[pos - 1] = "{HASH}"; 
    } 
    StringBuilder tempUrl = new StringBuilder();
    if (urlPaths.length > 0)
      for (int i = 0; i < urlPaths.length; i++) {
        if (i < urlPaths.length - 1) {
          tempUrl.append(urlPaths[i]).append("/");
        } else {
          tempUrl.append(urlPaths[i]);
        } 
      }  
    return tempUrl.toString();
  }
  
  public static void main(String[] args) {
    String[] urls = { 
        "/news/1", "/news/2?1=2", "/news/////2/edit", "//////news/2/read", "/path2/2/test", "/path2/3/test", "/path/3/////download", "/path/3/////download/1", "/path/3/////download/2", "/path/3/////download//3", 
        "/path/3/////a7bb7a9f-e3fc-4d6d-911f-5a7d90c0fccf//1", "/path/3/////293a7925-5d29-40f5-8e11-ed4c84b9b929//2", "/path/3/////b80c9c5f86de74f0090fc1a88b27ef34//2", "/path/3/////49ba59abbe56e057//2", "/path/3/////49ba59abbe56e057", "/path/3/////293a7925-5d29-40f5-8e11-ed4c84b9b929//49ba59abbe56e057", "/path/3/////download//2a8ba182-ed6e-4bb0-b4c5-0a0df4fd315a", "/path/293a7925-5d29-40f5-8e11-ed4c84b9b929/////download//3" };
  }
}
