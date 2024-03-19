package commmon;

import burp.BurpExtender;
import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import core.Config;

import java.util.HashMap;
import java.util.Map;

public class DnslogUtils {
    static String subdomain = null;


    public static class CallbackRedPT {

        public static Map<String, Object> getDomainAndApi(String domain) {
            Map<String, Object> values = new HashMap<>();
//            String apiUrl = "https://" + "callback.red" + "/get";
            String apiUrl = "https://" + domain + "/get";
            try {
                HttpRequest resp = HttpRequest.get(apiUrl).trustAllHosts().trustAllCerts().followRedirects(true).readTimeout(Config.TIMEOUT.intValue());
                if (resp.code() == 200) {
                    String body = resp.body();
                    if (body.contains("subdomain")) {
                        Gson gson = new Gson();
                        JsonObject jsonObject = gson.fromJson(body, JsonObject.class);
                        values.put("subdomain",jsonObject.get("subdomain").getAsString());
                        values.put("key",jsonObject.get("key").getAsString());
                        return values;
                    }
                    return values;
                }
                return values;
            } catch (Exception e) {
                e.printStackTrace();
                return values;
            }
        }

        public static String getLog(String domain,String key,String randomKey) {
//            BurpExtender.stdout.println("getlog!!!!2222222 request dnslog");
//            Map<String, Object> values = new HashMap<>();
//            String apiUrl = "https://" + "callback.red" + "/";
            String apiUrl = "https://" + domain + "/";
            String requestBody = "key={key}";
            String finRequestBody = requestBody.replace("{key}",key);

            try {
                HttpRequest resp = HttpRequest.post(apiUrl).trustAllHosts().trustAllCerts().followRedirects(true).readTimeout(Config.TIMEOUT.intValue()).send(finRequestBody);
                if (resp.code() == 200) {
                    String body = resp.body();
//                    BurpExtender.stdout.println(body);
                    if (body.contains(randomKey)) {
                        Gson gson = new Gson();
//                        JsonData jsonObject = gson.fromJson(body, JsonData.class);
                        JsonObject jsonObject = gson.fromJson(body, JsonObject.class);
                        // 输出键值对信息
//                        BurpExtender.stdout.println("Code: " + jsonObject.get("code").getAsInt());
                        String res = "";
                        JsonArray dataArray = jsonObject.getAsJsonArray("data");
                        for (JsonElement element : dataArray) {
                            JsonObject dataObject = element.getAsJsonObject();
                            if (dataObject.get("subdomain").getAsString().contains(randomKey)){

                                String res1 = "IP: " + dataObject.get("ip").getAsString() + " ";
                                String res2 = "Reqbody: " + dataObject.get("reqbody") + " ";
                                String res3 = "Subdomain: " + dataObject.get("subdomain").getAsString() + " ";
                                String res4 = "Time: " + dataObject.get("time").getAsString() + " ";
                                String res5 = "Type: " + dataObject.get("type").getAsString() + " ";

                                res = res + res1 + res2 + res3 + res4 + res5 + "\n\n";
                            }

                        }

                        return res;

                    } else if (body.contains("subdomain")) {
                        Gson gson = new Gson();
//                        JsonData jsonObject = gson.fromJson(body, JsonData.class);

                        JsonObject jsonObject = gson.fromJson(body, JsonObject.class);
                        // 输出键值对信息
                        System.out.println("Code: " + jsonObject.get("code").getAsInt());
                        JsonArray dataArray = jsonObject.getAsJsonArray("data");
                        for (JsonElement element : dataArray) {
                            JsonObject dataObject = element.getAsJsonObject();
                            BurpExtender.stdout.println("IP: " + dataObject.get("ip").getAsString());
                            BurpExtender.stdout.println("Reqbody: " + dataObject.get("reqbody"));
                            BurpExtender.stdout.println("Subdomain: " + dataObject.get("subdomain").getAsString());
                            BurpExtender.stdout.println("Time: " + dataObject.get("time").getAsString());
                            BurpExtender.stdout.println("Type: " + dataObject.get("type").getAsString());
                            BurpExtender.stdout.println();
                        }

                        return "";

                    } else {
                        System.out.println(body);
                        return "";
                    }
                }
                return "";
            } catch (Exception e) {
                e.printStackTrace();
                return "";
            }


        }
        public static String getLog(String domain,String key) {
            return getLog(domain,key,"");
        }


    }


    public static void main(String[] args) {
        Map<String, Object> res = CallbackRedPT.getDomainAndApi("callback.red");

        String subdomain = (String) res.get("subdomain");
        String apikey = (String) res.get("key");

        CallbackRedPT.getLog("callback.red","2466752d-85cf-46c5-ba12-2469b117b870");

    }
}

