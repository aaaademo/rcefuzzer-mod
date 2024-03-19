package core;

import java.io.File;
import java.util.ArrayList;

public class Config {
  public static boolean ALLOWED_PASSIVESCAN = true;
  
  public static String YAML_PATH = System.getProperty("user.dir") + File.separator + "rcefuzzer.yaml";
  
  public static Integer TIMEOUT = Integer.valueOf(60000);
  
  public static String HOST_WHITELIST_REG = ".*?";
  
  public static String HOST_BLACKLIST_REG = "(.+?)(gov\\.cn|edu\\.cn|tweb)(.+?)";
  
  public static String EXT_BLACKLIST = ".js|.css|.jpeg|.gif|.jpg|.png|.pdf|.rar|.zip|.docx|.doc";
  
  public static ArrayList<String> CACHE_DATA = new ArrayList<>();
  
  public static int requestCounts = 0;
}
