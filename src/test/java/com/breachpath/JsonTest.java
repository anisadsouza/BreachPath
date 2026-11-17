package com.breachpath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.breachpath.web.Json;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The small JSON reader and writer used by the REST API. */
class JsonTest {

    @Test
    void writesAndReadsNestedValues() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", "WS-Alice");
        m.put("score", 87);
        m.put("ratio", 0.5);
        m.put("ok", true);
        m.put("none", null);
        m.put("list", List.of(1, 2, 3));
        m.put("nested", Map.of("k", "v"));
        Map<String, Object> back = Json.parseObject(Json.write(m));
        assertEquals("WS-Alice", back.get("name"));
        assertEquals(87, ((Number) back.get("score")).intValue());
        assertEquals(0.5, ((Number) back.get("ratio")).doubleValue(), 0.0);
        assertEquals(Boolean.TRUE, back.get("ok"));
        assertEquals(3, ((List<?>) back.get("list")).size());
    }

    @Test
    void escapesQuotesBackslashesNewlinesAndControlCharacters() {
        String tricky = "say \"hi\"\\ path\nline2\ttab \u0001";
        Map<String, Object> back = Json.parseObject(Json.write(Map.of("s", tricky)));
        assertEquals(tricky, back.get("s"));
        assertTrue(!Json.write(Map.of("s", tricky)).contains("\n"), "raw newlines must be escaped");
    }

    @Test
    void parsesUnicodeEscapes() {
        assertEquals("café", Json.parseObject("{\"a\":\"caf\\u00e9\"}").get("a"));
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : new String[]{"", "   ", "{", "{\"a\":}", "{\"a\":1,}", "[1,2]", "{\"a\":1} extra",
                "{'a':1}", "{\"a\":\"unterminated}", "nul"}) {
            assertThrows(IllegalArgumentException.class, () -> Json.parseObject(bad));
        }
    }

    @Test
    void rejectsExcessiveNesting() {
        String deep = "[".repeat(5_000) + "]".repeat(5_000);
        assertThrows(IllegalArgumentException.class, () -> Json.parse(deep));
    }
}