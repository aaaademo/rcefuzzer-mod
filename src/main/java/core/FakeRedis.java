package core;

import java.util.ArrayList;

public class FakeRedis {
  public static ArrayList<String> data = new ArrayList<>();
  
  public static boolean isInCache(String src) {
    return data.contains(src);
  }
  
  public static void addToCache(String src) {
    data.add(src);
  }
}
