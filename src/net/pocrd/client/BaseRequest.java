package net.pocrd.client;

import java.io.InputStream;
import java.util.Random;

public abstract class BaseRequest<T> {
    protected ParameterList params             = new ParameterList();
    protected Response<T>   response           = new Response<T>();
    protected boolean       snRequired         = false;
    protected boolean       deviceTypeRequired = false;
    protected boolean       appidRequired      = false;
    protected boolean       eKeyPwdRequired    = false;
    long                    systime            = 0;
    int                     securityType       = 0;
    boolean                 ssl                = false;
    private String          methodName         = null;
    private String          cid                = null;
    private static Random   random             = new Random();

    public BaseRequest(String methodName, int securityType, String reqsig, boolean ssl) {
        this.securityType = securityType;
        this.methodName = methodName;
        params.put("method", methodName);

        if (reqsig != null) {
            params.put("reqsig", reqsig);
        }

        this.ssl = ssl;
        cid = String.valueOf(random.nextInt());
    }

    public String getCid() {
        return cid;
    }

    public String getMethodName() {
        return methodName;
    }

    public int getReturnCode() {
        return response.code;
    }

    public String getReturnMessage() {
        return response.message;
    }

    public long getSystime() {
        return systime;
    }

    public int getSecurityType() {
        return securityType;
    }

    public void putExt(String name, String value) {
        params.put(name, value);
    }

    @Override
    public String toString() {
        if (params != null) {
            StringBuilder sb = new StringBuilder(params.size() * 10);
            for (String key : params.keySet()) {
                sb.append(key);
                sb.append("=");
                sb.append(params.get(key));
                sb.append("&");
            }
            return sb.toString();
        }
        return "";
    }

    abstract protected T getResult(InputStream stream);

    void fillResponse(int code, int length, String msg, InputStream stream) {
        response.code = code;
        response.length = length;
        response.message = msg;
        if (stream != null) {
            response.result = getResult(stream);
        }
    }

    /**
     * �峰�褰��璇锋�杩������″�浣�
     */
    public T getResponse() {
        return response.result;
    }
}
