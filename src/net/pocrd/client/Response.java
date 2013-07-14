package net.pocrd.client;

import net.pocrd.apiRequest.ApiCode;

public class Response<T> {
    public int    code;
    public String message;
    public T      result;
    public int    length;

    public Response() {
        code = ApiCode.NOT_INIT;
    }
}
