package commmon;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import core.Config;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;

public class CommonUtils {
  public static String getRandomString(int length) {
    String str = "abcdefghijklmnopqrstuvwxyz0123456789";
    SecureRandom random = new SecureRandom();
    StringBuffer sb = new StringBuffer();
    for (int i = 0; i < length; i++) {
      int number = random.nextInt(str.length());
      sb.append(str.charAt(number));
    } 
    return sb.toString();
  }
  
  public static boolean isMatch(String regx, String str) {
    Pattern pat = Pattern.compile("[\\w]+[\\.](" + regx + ")", 2);
    Matcher mc = pat.matcher(str);
    if (mc.find())
      return true; 
    return false;
  }
  
  public static boolean isBase64(String str) {
    if (str.length() > 4 && StringUtils.isAsciiPrintable(new String(Base64.getDecoder().decode(str))))
      return true; 
    return false;
  }
  
  public static boolean isEscape(String str) {
    if (str.contains("\\"))
      return true; 
    return false;
  }
  
  public static void main(String[] args) throws Exception {}
  
  public static boolean isExtMatch(String url) {
    String[] exts = Config.EXT_BLACKLIST.split("\\|");
    for (String ext : exts) {
      if (url.endsWith(ext))
        return true; 
    } 
    return false;
  }
  
  public static JsonElement jsonPollution(JsonElement jsonElement, String payload) {
    if (jsonElement.isJsonObject()) {
      Set<Map.Entry<String, JsonElement>> jsonMap = jsonElement.getAsJsonObject().entrySet();
      for (Map.Entry<String, JsonElement> jsonData : jsonMap) {
        if (!((JsonElement)jsonData.getValue()).isJsonArray()) {
          if (((JsonElement)jsonData.getValue()).getAsJsonPrimitive().isString()) {
            String temp = jsonPollution(((JsonElement)jsonData.getValue()).getAsString(), payload);
            jsonElement.getAsJsonObject().add(jsonData.getKey(), (new Gson()).toJsonTree(temp));
            continue;
          } 
          if (((JsonElement)jsonData.getValue()).isJsonObject()) {
            JsonElement jsonElement2 = jsonPollution(jsonData.getValue(), payload);
            jsonElement.getAsJsonObject().add(jsonData.getKey(), jsonElement2);
          } 
          continue;
        } 
        JsonArray jsonArray = ((JsonElement)jsonData.getValue()).getAsJsonArray();
        for (JsonElement jsonElement3 : jsonArray)
          jsonPollution(jsonElement3, payload); 
      } 
    } else if (jsonElement.isJsonArray()) {
      JsonArray jsonArray = jsonElement.getAsJsonArray();
      for (JsonElement jsonElement3 : jsonArray)
        jsonPollution(jsonElement3, payload); 
    } 
    return jsonElement;
  }
  
  public static String jsonPollution(String paramValue, String payload) {
    String result;
    boolean isBase64 = false;
    boolean isEscape = false;
    try {
      JsonParser jsonParser = new JsonParser();
      JsonElement jsonElement = jsonParser.parse(paramValue);
      if (jsonElement.isJsonPrimitive()) {
        String str = payload;
        throw new Exception();
      } 
      result = jsonPollution(jsonElement, payload).toString();
    } catch (Exception e) {
      try {
        String tmp = new String(Base64.getDecoder().decode(paramValue));
        if (StringUtils.isAsciiPrintable(tmp)) {
          paramValue = tmp;
          isBase64 = true;
        } 
      } catch (Exception e2) {
        if (paramValue.contains("\\")) {
          paramValue = StringEscapeUtils.unescapeJava(paramValue);
          isEscape = true;
        } 
      } finally {
        try {
          JsonParser jsonParser2 = new JsonParser();
          JsonElement jsonElement2 = jsonParser2.parse(paramValue);
          if (jsonElement2.isJsonPrimitive()) {
            result = payload;
          } else {
            result = jsonPollution(jsonElement2, payload).toString();
          } 
        } catch (Exception e2) {
          result = paramValue;
        } 
      } 
    } 
    if (isBase64) {
      while (result.contains(String.format("\"%s\"", new Object[] { payload }))) {
        result = result.replace(String.format("\"%s\"", new Object[] { payload }), payload);
      } 
      return new String(Base64.getEncoder().encode(result.getBytes()));
    } 
    if (isEscape) {
      System.out.println(1);
      System.out.println(result);
      while (result.contains(String.format("\\\\\"%s\\\\\"", new Object[] { payload }))) {
        result = result.replace(String.format("\\\\\"%s\\\\\"", new Object[] { payload }), payload);
      } 
      System.out.println(result);
      System.out.println(1);
      return StringEscapeUtils.escapeJava(result);
    } 
    return result;
  }
}
