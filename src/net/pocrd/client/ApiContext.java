package net.pocrd.client;

import java.io.InputStream;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.pocrd.util.Base64;

public class ApiContext {
    private static final Object signLocker      = new Object();

    private X509Certificate     certificate     = null;
    private String              sigAlgName      = null;
    private PrivateKey          pk              = null;
    private String              token           = null;
    private String              sn              = null;
    private String              deviceType      = null;
    private String              appid           = null;
    private String              location        = null;
    private String              version         = null;
    private String              sdid            = null;
    private String              apn             = null;
    private String              vercode         = null;
    private long                tokenExpireTime = 0;

    public ApiContext(String vercode) {
        this.vercode = vercode;
    }

    public void setCertificate(X509Certificate cert, PrivateKey privateKey) {
        certificate = cert;
        sigAlgName = certificate.getSigAlgName();
        pk = privateKey;

        String subject = certificate.getSubjectDN().getName();
        int ouStart = subject.indexOf("OU=");
        int ouEnd = subject.indexOf(",", ouStart);
        String ou = null;
        if (ouEnd != -1) {
            ou = subject.substring(ouStart + 3, ouEnd);
        } else {
            ou = subject.substring(ouStart + 3);
        }
        int cnStart = subject.indexOf("CN=");
        int cnEnd = subject.indexOf(",", cnStart);
        String cn = null;
        if (cnEnd != -1) {
            cn = subject.substring(cnStart + 3, cnEnd);
        } else {
            cn = subject.substring(cnStart + 3);
        }
        sn = ou + cn;
        int dtStart = subject.indexOf("1.2.7.21.4.8.4.14.3=");
        int dtEnd = subject.indexOf(",", dtStart);
        if (dtEnd != -1) {
            deviceType = subject.substring(dtStart + 20, dtEnd);
        } else {
            deviceType = subject.substring(dtStart + 20);
        }
        int appidStart = subject.indexOf("1.2.7.21.4.8.4.14.2=");
        int appidEnd = subject.indexOf(",", appidStart);
        if (appidEnd != -1) {
            appid = subject.substring(appidStart + 20, appidEnd);
        } else {
            appid = subject.substring(appidStart + 20);
        }
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getLocation() {
        return location;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getVersion() {
        return version;
    }

    public void setToken(String tk) {
        token = tk;
    }

    public String getToken() {
        return token;
    }

    public String getSN() {
        return sn;
    }

    public String getDeviceType() {
        return deviceType;
    }

    public String getAppId() {
        return appid;
    }

    public String getSdid() {
        return sdid;
    }

    public void setSdid(String sdid) {
        this.sdid = sdid;
    }

    public String getApn() {
        return apn;
    }

    public void setApn(String apn) {
        this.apn = apn;
    }

    public void setTokenExpireTime(long time) {
        tokenExpireTime = time;
    }

    public long getTokenExpireTime() {
        return tokenExpireTime;
    }

    public boolean hasCertificate() {
        return pk != null;
    }

    public String computeEKeyPwd(String challenge) {
        try {
            byte[] bytes = Base64.decode(challenge.getBytes("utf-8"), Base64.NO_WRAP);
            Signature sig = Signature.getInstance(sigAlgName);
            sig.initSign(pk);
            sig.update(bytes);
            return new String(Base64.encode(sig.sign(), Base64.NO_WRAP), "utf-8");
        } catch (Exception e) {
            return null;
        }
    }

    public String getParameterString(BaseRequest<?> request) {
        ParameterList params = request.params;
        params.put("format", "protobuf");
        if (location != null && !params.containsKey("lo")) {
            params.put("lo", location);
        }
        if (version != null && !params.containsKey("version")) {
            params.put("version", version);
        }
        if (request.appidRequired) {
            params.put("appid", appid);
        }
        if (request.deviceTypeRequired) {
            params.put("deviceType", deviceType);
        }
        if (request.eKeyPwdRequired) {
            String challenge = params.get("challenge");
            if (challenge != null && challenge.length() > 0) {
                params.put("ekeypwd", computeEKeyPwd(challenge));
            }
        }
        if (request.snRequired) {
            params.put("sn", sn);
        }

        if (sn != null && !params.containsKey("c_sn")) {
            params.put("c_sn", sn);
        }

        if (appid != null && !params.containsKey("c_appid")) {
            params.put("c_appid", appid);
        }

        if (sdid != null && sdid.length() > 0 && !params.containsKey("c_sdid")) {
            params.put("c_sdid", sdid);
        }

        if (apn != null && !params.containsKey("c_apn")) {
            params.put("c_apn", apn);
        }

        if (vercode != null && !params.containsKey("c_ver")) {
            params.put("c_ver", vercode);
        }
        return getParameterStringInternal(params, request.securityType);
    }

    public String getParameterString(BaseRequest<?>[] requests) {
        int securityType = 0;
        ParameterList params = new ParameterList(requests.length * 2);
        StringBuilder methodNames = new StringBuilder();

        for (int i = 0; i < requests.length; i++) {
            BaseRequest<?> req = requests[i];

            securityType = Math.max(securityType, req.securityType);
            for (String key : req.params.keySet()) {
                if ("method".equals(key)) {
                    methodNames.append(req.params.get(key));
                    methodNames.append(",");
                } else if ("reqsig".equals(key)) {
                    if (!params.containsKey("reqsig")) {
                        params.put("reqsig", req.params.get("reqsig"));
                    }
                } else if ("version".equals(key)) {
                    if (!params.containsKey("version")) {
                        params.put("version", req.params.get("version"));
                    }
                } else {
                    params.put(i + "_" + key, req.params.get(key));
                }
            }

            if (req.appidRequired) {
                params.put(i + "_appid", appid);
            }

            if (req.deviceTypeRequired) {
                params.put(i + "_deviceType", deviceType);
            }

            if (req.eKeyPwdRequired) {
                String challenge = req.params.get("challenge");
                if (challenge != null && challenge.length() > 0) {
                    params.put(i + "_ekeypwd", computeEKeyPwd(challenge));
                }
            }

            if (req.snRequired) {
                params.put(i + "_sn", sn);
            }
        }
        methodNames.setLength(methodNames.length() - 1);
        params.put("method", methodNames.toString());

        params.put("format", "protobuf");
        if (location != null && !params.containsKey("lo")) {
            params.put("lo", location);
        }

        if (version != null && !params.containsKey("version")) {
            params.put("version", version);
        }

        if (sn != null && !params.containsKey("c_sn")) {
            params.put("c_sn", sn);
        }

        if (appid != null && !params.containsKey("c_appid")) {
            params.put("c_appid", appid);
        }

        if (sdid != null && sdid.length() > 0 && !params.containsKey("c_sdid")) {
            params.put("c_sdid", sdid);
        }

        if (apn != null && !params.containsKey("c_apn")) {
            params.put("c_apn", apn);
        }

        if (vercode != null && !params.containsKey("c_ver")) {
            params.put("c_ver", vercode);
        }

        return getParameterStringInternal(params, securityType);
    }

    public void fillResponse(BaseRequest<?> request, InputStream data) {
		if (data != null) {
			try {
				byte[] bs = new byte[4];
				data.read(bs);
				int i0 = bs[0] >= 0 ? bs[0] : bs[0] + 256;
				int i1 = bs[1] >= 0 ? bs[1] : bs[1] + 256;
				int i2 = bs[2] >= 0 ? bs[2] : bs[2] + 256;
				int i3 = bs[3] >= 0 ? bs[3] : bs[3] + 256;
				int index = i0 + (i1 << 8) + (i2 << 16) + (i3 << 24);
				Api_CallResponse resp = ApiCallResponse.Api_CallResponse
						.parseFrom(new LimitedInputStream(data, index - 4));
				if (resp != null) {
					request.systime = resp.getSystime();
					List<Api_CallStatus> statList = resp.getResponseList();
					if (statList != null && statList.size() > 0) {
						Api_CallStatus status = statList.get(0);
						request.fillResponse(Ï
								status.getCode(),
								status.getLength(),
								status.getMessage(),
								status.getLength() == 0 ? null
										: new LimitedInputStream(data, status
												.getLength()));
					}
				}
			} finally {
				if (data != null) {
					data.close();
				}
			}
		}
	}

    public void fillError(BaseRequest<?> request, int code) {
        request.fillResponse(code, 0, "", (InputStream)null);
    }

    public long fillResponse(BaseRequest<?>[] requests, InputStream data) {
        if (data != null) {
            byte[] bs = new byte[4];
            try {
                data.read(bs);
                int i0 = bs[0] >= 0 ? bs[0] : bs[0] + 256;
                int i1 = bs[1] >= 0 ? bs[1] : bs[1] + 256;
                int i2 = bs[2] >= 0 ? bs[2] : bs[2] + 256;
                int i3 = bs[3] >= 0 ? bs[3] : bs[3] + 256;
                int index = i0 + (i1 << 8) + (i2 << 16) + (i3 << 24);
                Api_CallResponse resp = ApiCallResponse.Api_CallResponse.parseFrom(new LimitedInputStream(data, index - 4));
                if (resp != null) {
                    long systime = resp.getSystime();
                    List<Api_CallStatus> statList = resp.getResponseList();
                    int respSize = statList.size();
                    if (respSize != requests.length) throw new RuntimeException("request size unmatch.");
                    for (int i = 0; i < respSize; i++) {
                        Api_CallStatus status = statList.get(i);
                        BaseRequest<?> request = requests[i];
                        request.systime = systime;
                        request.fillResponse(status.getCode(), status.getLength(), status.getMessage(), status.getLength() == 0 ? null
                                : new LimitedInputStream(data, status.getLength()));
                    }
                    return systime;
                }
            } finally {
                if (data != null) {
                    data.close();
                }
            }
        }
        return -1;
    }

    public String getCertEncoded() {
        if (certificate == null) {
            throw new RuntimeException("certificate is null.");
        }
        try {
            return Base64.encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("certificate error.", e);
        }
    }

    public void fillError(BaseRequest<?>[] requests, int code) {
        int size = requests.length;
        for (int i = 0; i < size; i++) {
            requests[i].fillResponse(code, 0, "", (InputStream)null);
        }
    }

    private void signRequest(ParameterList params, int securityType) {
        if (params.containsKey("sig")) return;
        try {
            StringBuilder sb = new StringBuilder(params.size() * 5);
            List<String> paramNames = new ArrayList<String>(params.keySet());
            Collections.sort(paramNames);
            for (String key : paramNames) {
                sb.append(key);
                sb.append('=');
                sb.append(params.get(key));
            }

            if (securityType == 0) {
                sb.append("CLOUDARY@snda.com");
                MessageDigest sha = MessageDigest.getInstance("SHA1");
                params.put("sig", new String(Base64.encode(sha.digest(sb.toString().toLowerCase().getBytes("utf-8")), Base64.NO_WRAP), "utf-8"));
            } else {
                if (certificate == null) {
                    throw new RuntimeException("certificate is null.");
                }
                byte[] bs = sb.toString().toLowerCase().getBytes("utf-8");
                Signature sig = Signature.getInstance(sigAlgName);
                byte[] s = null;
                // 对签名部分进行同步
                synchronized (signLocker) {
                    sig.initSign(pk);
                    sig.update(bs);
                    s = sig.sign();
                }
                String signature = new String(Base64.encode(s, Base64.NO_WRAP), "utf-8");
                params.put("sig", signature);
            }
        } catch (Exception e) {
            throw new RuntimeException("sign url failed.", e);
        }
    }

    private String getParameterStringInternal(ParameterList params, int securityType) {
        if (token != null) {
            params.put("token", token);
        } else if (securityType > 0) {
            throw new ApiException(ApiCode.INVALID_TOKEN);
        }

        signRequest(params, securityType);

        if (params.size() > 0) {
            try {
                StringBuilder sb = new StringBuilder(params.size() * 7);
                for (String key : params.keySet()) {
                    sb.append(key);
                    sb.append('=');
                    sb.append(URLEncoder.encode(params.get(key), "utf-8"));
                    sb.append('&');
                }
                sb.setLength(sb.length() - 1);
                return sb.toString();
            } catch (Exception e) {
                throw new RuntimeException("invalid request", e);
            }
        }
        throw new RuntimeException("invalid request");
    }
}
