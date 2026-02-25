package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.Collections;

/**
 * Centralized JSON serialization for HTTP responses and error payloads.
 * Single place for JSON format and escaping.
 */
public final class JsonHelper {

    private static final Gson GSON = new GsonBuilder().create();

    private JsonHelper() {}

    /** Serialize any object to JSON (lists, maps, primitives). */
    public static String toJson(Object o) {
        if (o == null) return "null";
        return GSON.toJson(o);
    }

    /** Build a JSON object with a single "error" key. Used by safeHandler and validation. */
    public static String errorJson(String message) {
        return GSON.toJson(Collections.singletonMap("error", message != null ? message : "Unknown error"));
    }
}
