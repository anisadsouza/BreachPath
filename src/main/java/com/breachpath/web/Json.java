package com.breachpath.web;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON writer and parser, enough for this API (no external library).
 * Values are Map (objects), List (arrays), String, Number, Boolean and null.
 */
public final class Json {
    private static final int MAX_DEPTH = 32;

    private Json() {
    }

    // ---- writing ----------------------------------------------------------------------------

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String s) {
            quote(sb, s);
        } else if (v instanceof Boolean b) {
            sb.append(b ? "true" : "false");
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            sb.append(Double.isNaN(d) || Double.isInfinite(d) ? "null" : String.valueOf(d));
        } else if (v instanceof Number n) {
            sb.append(n);
        } else if (v instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                quote(sb, String.valueOf(e.getKey()));
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof Iterable<?> it) {
            sb.append('[');
            boolean first = true;
            for (Object o : it) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                write(sb, o);
            }
            sb.append(']');
        } else if (v instanceof int[] arr) {
            sb.append('[');
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(arr[i]);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("Cannot write " + v.getClass().getName() + " as JSON");
        }
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c == ' ' || c == ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // ---- parsing ----------------------------------------------------------------------------

    /** Thrown for text that is not valid JSON. */
    public static final class ParseException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;

        public ParseException(String message) {
            super(message);
        }
    }

    /** Parses one JSON value; whitespace around it is allowed, anything else after it is an error. */
    public static Object parse(String text) {
        if (text == null) {
            throw new ParseException("Empty JSON body");
        }
        Parser p = new Parser(text);
        p.skipWs();
        if (p.atEnd()) {
            throw new ParseException("Empty JSON body");
        }
        Object v = p.value(0);
        p.skipWs();
        if (!p.atEnd()) {
            throw p.error("Unexpected text after the JSON value");
        }
        return v;
    }

    /** Parses a JSON object body; anything else is an error. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map)) {
            throw new ParseException("Expected a JSON object");
        }
        return (Map<String, Object>) v;
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        ParseException error(String msg) {
            return new ParseException("Invalid JSON at position " + pos + ": " + msg);
        }

        void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) {
                pos++;
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("nesting is too deep");
            }
            if (atEnd()) {
                throw error("unexpected end");
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    return literal("true", Boolean.TRUE);
                case 'f':
                    return literal("false", Boolean.FALSE);
                case 'n':
                    return literal("null", null);
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw error("unexpected character '" + c + "'");
            }
        }

        Object literal(String word, Object value) {
            if (!s.startsWith(word, pos)) {
                throw error("expected " + word);
            }
            pos += word.length();
            return value;
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++;
            skipWs();
            if (!atEnd() && s.charAt(pos) == '}') {
                pos++;
                return m;
            }
            while (true) {
                skipWs();
                if (atEnd() || s.charAt(pos) != '"') {
                    throw error("expected a string key");
                }
                String key = string();
                skipWs();
                if (atEnd() || s.charAt(pos) != ':') {
                    throw error("expected ':'");
                }
                pos++;
                skipWs();
                m.put(key, value(depth + 1));
                skipWs();
                if (atEnd()) {
                    throw error("unexpected end in object");
                }
                char c = s.charAt(pos++);
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    pos--;
                    throw error("expected ',' or '}'");
                }
            }
        }

        List<Object> array(int depth) {
            List<Object> list = new ArrayList<>();
            pos++;
            skipWs();
            if (!atEnd() && s.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWs();
                list.add(value(depth + 1));
                skipWs();
                if (atEnd()) {
                    throw error("unexpected end in array");
                }
                char c = s.charAt(pos++);
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    pos--;
                    throw error("expected ',' or ']'");
                }
            }
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            pos++;
            while (true) {
                if (atEnd()) {
                    throw error("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c < 0x20) {
                    pos--;
                    throw error("control character in string");
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (atEnd()) {
                    throw error("unterminated escape");
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) {
                            throw error("short \\u escape");
                        }
                        try {
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw error("bad \\u escape");
                        }
                        pos += 4;
                    }
                    default -> {
                        pos--;
                        throw error("bad escape '\\" + e + "'");
                    }
                }
            }
        }

        Number number() {
            int start = pos;
            if (s.charAt(pos) == '-') {
                pos++;
            }
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
            boolean fraction = false;
            if (pos < s.length() && s.charAt(pos) == '.') {
                fraction = true;
                pos++;
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                fraction = true;
                pos++;
                if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < s.length() && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            String t = s.substring(start, pos);
            try {
                if (fraction) {
                    return Double.parseDouble(t);
                }
                long l = Long.parseLong(t);
                return l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE ? (Number) (int) l : (Number) l;
            } catch (NumberFormatException ex) {
                pos = start;
                throw error("bad number '" + t + "'");
            }
        }
    }
}