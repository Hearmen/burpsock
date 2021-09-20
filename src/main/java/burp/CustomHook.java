package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

public class CustomHook {
    @JSONField(name = "packageName") //
    private String mPackageName;
    @JSONField(name = "className") //
    private String mClassName;
    @JSONField(name = "methodName") //
    private String mMethodName;
    @JSONField(name = "parameters") //
    private String[] mParameters; // null and  length==0
    @JSONField(name = "parameterEncoders")
    private List<CustomHook> mParameterEncoders;
    @JSONField(name = "isNeedForwardServer")
    private boolean mIsNeedForwardServer;  //
    @JSONField(name = "sendOrRecv")
    private boolean mSendOrRecv;   // send => "msg_to"; recv => "msg_from"
    @JSONField(name = "isInterceptorHook")
    private boolean mIsInterceptorHook; // intercepte hook,or just export //
    @JSONField(name = "os")
    private int os; //
    @JSONField(name = "uid")
    private String uid;

    public CustomHook(String packageName, String className, int os, String methodName, String[] parameters, List<CustomHook> parameterEncoders, boolean isNeedForwardServer, boolean sendOrRecv,boolean isInterceptorHook) {
        this.mPackageName = packageName;
        this.mClassName = className;
        this.os = os;
        this.mMethodName = methodName;
        this.mParameters = parameters;
        this.mParameterEncoders = parameterEncoders;
        this.mIsNeedForwardServer = isNeedForwardServer;
        this.mSendOrRecv = sendOrRecv;
        this.mIsInterceptorHook = isInterceptorHook;
        this.uid = UUID.randomUUID().toString().substring(0, 8);
    }

    public String getPackageName(){ return mPackageName; }
    public String getClassName(){ return mClassName;}
    public String getMethodName(){ return mMethodName;}
    public String[] getParameters(){ return mParameters;}
    public CustomHook getParameterEncoder(int index){return mParameterEncoders.get(index);}
    public List<CustomHook> getParameterEncoders(){ return mParameterEncoders;}
    public boolean isNeedForwardServer(){return mIsNeedForwardServer;}
    public boolean getSendOrRecv(){ return mSendOrRecv; }
    public boolean isInterceptorHook(){ return mIsInterceptorHook; }
    public int getOs(){ return os;}

    public void setPackageName(String packageName) {
        this.mPackageName = mPackageName;
    }

    public void setClassName(String className) {
        this.mClassName = className;
    }

    public void setMethodName(String methodName) {
        this.mMethodName = methodName;
    }

    public void setParameters(String[] parameters) {
        this.mParameters = mParameters;
    }

    public void setIsNeedForwardServer(boolean isNeedForwardServer) {
        this.mIsNeedForwardServer = isNeedForwardServer;
    }

    public void setParametersEncoder(List<CustomHook> parameterEncoders) {
        this.mParameterEncoders = parameterEncoders;
    }

    public void setSendOrRecv(boolean sendOrRecv) {
        this.mSendOrRecv = sendOrRecv;
    }

    public void setIsInterceptorHook(boolean isInterceptorHook) {
        this.mIsInterceptorHook = isInterceptorHook;
    }

    public void setOs(int os) {
        this.os = os;
    }

    public void setUid(String uid){this.uid = uid;}

    @Override
    public String toString() {
        return mPackageName+"."+mClassName+"."+mMethodName+"_"+ uid;
    }

    public String toJSON(){
        return JSON.toJSONString(this);
    }

    public static CustomHook fromJSON(String jsonString){
        return JSON.parseObject(jsonString,CustomHook.class);
    }
}
