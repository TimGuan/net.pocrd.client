package net.pocrd.client;

import com.yuncheng.api.request.ApiCode;

public class Response<T> {
    public int    code;
    public String message;
    public T      result;
    public int    length;

    public Response() {
        code = ApiCode.NOT_INIT;
    }
}
