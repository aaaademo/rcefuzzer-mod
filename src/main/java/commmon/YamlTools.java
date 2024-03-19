//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package commmon;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Map;
import org.yaml.snakeyaml.Yaml;

public class YamlTools {
  Map<String, Object> properties;

  public YamlTools() {
  }

  public YamlTools(String filePath) {
    InputStream inputStream = null;

    try {
      inputStream = new FileInputStream(filePath);
    } catch (FileNotFoundException var4) {
      var4.printStackTrace();
    }

    Yaml yaml = new Yaml();
    this.properties = (Map)yaml.loadAs(inputStream, Map.class);
  }

  public void initWithString(String content) {
    Yaml yaml = new Yaml();
    this.properties = (Map)yaml.loadAs(content, Map.class);
  }

  public <T> T getValueByKey(String key, T defaultValue) {
    String separator = ".";
    String[] separatorKeys = null;
    Object res;
    if (key.contains(separator)) {
      separatorKeys = key.split("\\.");
      res = null;
      Object tempObject = this.properties;

      for(int i = 0; i < separatorKeys.length; ++i) {
        String innerKey = separatorKeys[i];
        Integer index = null;
        Map<String, Object> mapTempObj = (Map)tempObject;
        Object object = mapTempObj.get(innerKey);
        if (object == null) {
          return defaultValue;
        }

        Object targetObj = object;
        if (index != null) {
          targetObj = ((ArrayList)object).get(index);
        }

        tempObject = targetObj;
        if (i == separatorKeys.length - 1) {
          return (T) targetObj;
        }
      }

      return null;
    } else {
      res = this.properties.get(key);
      return res == null ? defaultValue : (T) res;
    }
  }
}
