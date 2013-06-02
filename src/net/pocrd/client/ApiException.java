package net.pocrd.client;

public class ApiException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public int code = 0;

    public ApiException(int statusCode){
        this.code = statusCode;
    }
    
    public ApiException(String msg, int statusCode){
        super(msg);
        this.code = statusCode;
    }
    
    public ApiException(Exception e, String msg, int statusCode){
        super(msg, e);
        this.code = statusCode;
    }
    
    public int getCode(){
        return code;
    }
}
