package net.pocrd.client;

import java.util.HashMap;
import java.util.Set;

public class ParameterList {
    private HashMap<String, String> params = null;

    public ParameterList() {
        params = new HashMap<String, String>();
    }

    public ParameterList(int initialCapacity) {
        params = new HashMap<String, String>(initialCapacity);
    }

    public final void put(String name, String value) {
        if (name == null || name.length() == 0) return;
        if (value == null) value = "";
        params.put(name.toLowerCase(), value);
    }

    public final void put(String name, boolean value) {
        if (name == null || name.length() == 0) return;
        params.put(name.toLowerCase(), String.valueOf(value));
    }

    public final Set<String> keySet() {
        return params.keySet();
    }

    public final String get(String key) {
        return params.get(key);
    }

    public final boolean containsKey(String key) {
        return params.containsKey(key);
    }

    public final int size() {
        return params.size();
    }
}
