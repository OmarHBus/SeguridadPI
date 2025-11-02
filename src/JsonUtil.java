import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON utilities supporting objects with string values and
 * arrays of such objects. Designed to avoid the unsafe string-search
 * approach previously used while keeping the project dependency-free.
 */
public final class JsonUtil {

    private static final int DEFAULT_MAX_STRING_LENGTH = 8_192;

    private JsonUtil() { }

    public static Map<String, String> parseObject(String json) {
        return parseObject(json, 64, DEFAULT_MAX_STRING_LENGTH);
    }

    public static Map<String, String> parseObject(String json, int maxEntries, int maxStringLength) {
        Parser parser = new Parser(json, maxStringLength);
        Map<String, String> map = parser.readObject(maxEntries);
        parser.ensureEof();
        return map;
    }

    public static List<Map<String, String>> parseArrayOfObjects(String json) {
        return parseArrayOfObjects(json, 256, 32, DEFAULT_MAX_STRING_LENGTH);
    }

    public static List<Map<String, String>> parseArrayOfObjects(String json, int maxItems, int maxEntriesPerItem, int maxStringLength) {
        Parser parser = new Parser(json, maxStringLength);
        List<Map<String, String>> list = parser.readArrayOfObjects(maxItems, maxEntriesPerItem);
        parser.ensureEof();
        return list;
    }

    public static String escape(String value) {
        if (value == null) return "";
        StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (ch < 0x20) {
                        sb.append(String.format("\\u%04x", (int) ch));
                    } else {
                        sb.append(ch);
                    }
            }
        }
        return sb.toString();
    }

    public static String quote(String value) {
        return '"' + escape(value) + '"';
    }

    private static final class Parser {
        private final char[] chars;
        private final int maxStringLength;
        private int pos;

        private Parser(String input, int maxStringLength) {
            if (input == null) {
                throw new IllegalArgumentException("JSON input is null");
            }
            this.chars = input.trim().toCharArray();
            this.maxStringLength = maxStringLength;
            this.pos = 0;
        }

        private void ensureEof() {
            skipWs();
            if (!isEof()) {
                throw new IllegalArgumentException("Unexpected trailing data in JSON");
            }
        }

        private boolean isEof() { return pos >= chars.length; }

        private void skipWs() {
            while (!isEof()) {
                char ch = chars[pos];
                if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private Map<String, String> readObject(int maxEntries) {
            skipWs();
            expect('{');
            Map<String, String> map = new LinkedHashMap<>();
            skipWs();
            if (peek('}')) {
                pos++; // consume closing brace
                return map;
            }
            int entries = 0;
            while (true) {
                entries++;
                if (entries > maxEntries) {
                    throw new IllegalArgumentException("JSON object exceeds maximum entries");
                }
                String key = readString();
                if (map.containsKey(key)) {
                    throw new IllegalArgumentException("Duplicate key: " + key);
                }
                skipWs();
                expect(':');
                skipWs();
                String value = readValue();
                map.put(key, value);
                skipWs();
                if (peek('}')) {
                    pos++;
                    break;
                }
                expect(',');
                skipWs();
            }
            return map;
        }

        private List<Map<String, String>> readArrayOfObjects(int maxItems, int maxEntriesPerItem) {
            skipWs();
            expect('[');
            List<Map<String, String>> list = new ArrayList<>();
            skipWs();
            if (peek(']')) {
                pos++;
                return list;
            }
            int items = 0;
            while (true) {
                items++;
                if (items > maxItems) {
                    throw new IllegalArgumentException("JSON array exceeds maximum length");
                }
                Map<String, String> obj = readObject(maxEntriesPerItem);
                list.add(obj);
                skipWs();
                if (peek(']')) {
                    pos++;
                    break;
                }
                expect(',');
                skipWs();
            }
            return list;
        }

        private String readValue() {
            skipWs();
            if (peek('"')) {
                return readString();
            }
            if (peek('n')) { return readLiteral("null"); }
            if (peek('t')) { return readLiteral("true"); }
            if (peek('f')) { return readLiteral("false"); }
            throw new IllegalArgumentException("Unsupported JSON value; only strings, true, false, null allowed");
        }

        private String readLiteral(String literal) {
            for (int i = 0; i < literal.length(); i++) {
                if (isEof() || chars[pos + i] != literal.charAt(i)) {
                    throw new IllegalArgumentException("Invalid JSON literal");
                }
            }
            pos += literal.length();
            return literal;
        }

        private String readString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (isEof()) {
                    throw new IllegalArgumentException("Unterminated JSON string");
                }
                char ch = chars[pos++];
                if (ch == '"') {
                    break;
                }
                if (ch == '\\') {
                    if (isEof()) {
                        throw new IllegalArgumentException("Bad escape in JSON string");
                    }
                    char esc = chars[pos++];
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            sb.append(readUnicodeEscape());
                            break;
                        default:
                            throw new IllegalArgumentException("Unsupported escape sequence: \\" + esc);
                    }
                } else {
                    if (ch < 0x20) {
                        throw new IllegalArgumentException("Control character in JSON string");
                    }
                    sb.append(ch);
                }
                if (sb.length() > maxStringLength) {
                    throw new IllegalArgumentException("JSON string exceeds maximum length");
                }
            }
            return sb.toString();
        }

        private char readUnicodeEscape() {
            if (pos + 4 > chars.length) {
                throw new IllegalArgumentException("Incomplete unicode escape");
            }
            int code = 0;
            for (int i = 0; i < 4; i++) {
                char ch = chars[pos++];
                int digit = Character.digit(ch, 16);
                if (digit < 0) {
                    throw new IllegalArgumentException("Bad unicode escape sequence");
                }
                code = (code << 4) | digit;
            }
            return (char) code;
        }

        private boolean peek(char expected) {
            return !isEof() && chars[pos] == expected;
        }

        private void expect(char expected) {
            if (isEof() || chars[pos] != expected) {
                throw new IllegalArgumentException("Expected '" + expected + "'");
            }
            pos++;
        }
    }
}

