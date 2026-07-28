package demo;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GreeterTest {
    @Test
    void greetsWithEscapedName() {
        assertEquals("Hello, World!", new Greeter().greet("World"));
    }
}
