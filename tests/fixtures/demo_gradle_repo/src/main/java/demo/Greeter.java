package demo;

import org.apache.commons.text.StringEscapeUtils;

public class Greeter {
    public String greet(String name) {
        return "Hello, " + StringEscapeUtils.escapeHtml4(name) + "!";
    }
}
