package burp;

public class FridaTemplate {
    public static final String fridaNormalTemplate="Java.perform(function(){\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.implementation = function (){\n" +
            "        send(\"Enter %s.%s\");\n" +
            "        var rlt = %s.%s.apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaOverloadTemplate="Java.perform(function(){\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.overload(%s).implementation = function (){\n" +
            "        send(\"Enter %s.%s\");\n" +
            "        var rlt = %s.%s.overload(%s).apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaInterceptorTemplate = "Java.perform(function(){\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.implementation = function (){\n" +
            "        send(\"Enter %s.%s\");\n" +
            "        var rlt = %s.%s.apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaInterceptorOverloadTemplate = "Java.perform(function(){\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.overload(%s).implementation = function (){\n" +
            "        send(\"Enter %s.%s\");\n" +
            "        var rlt = %s.%s.overload(%s).apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaForwardTemplate="Java.perform(function(){\n" +
            "    fucntion Encode(arg){\n" +
            "        return arg;\n" +
            "    }\n" +
            "    function Decode(arg){\n" +
            "        return arg;\n" +
            "    }\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.implementation = function (){\n" +
            "        var originData = null;\n" +
            "        var modifyData = null;\n" +
            "        originData = Encode(arguments[0]);\n" +
            "        send({\"from\":\"jscode\",'payload':originData,'msg-type':'%s'});\n" +
            "        var op = recv('python_send',function(value){\n" +
            "            modifyData = value.payload;\n" +
            "        })\n" +
            "        op.wait();\n" +
            "        arguments[0] = Decode(modifyData);\n" +
            "        var rlt = %s.%s.apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaForwardOverloadTemplate="Java.perform(function(){\n" +
            "    fucntion Encode(arg){\n" +
            "        return arg;\n" +
            "    }\n" +
            "    function Decode(arg){\n" +
            "        return arg;\n" +
            "    }\n" +
            "    var %s = Java.use(\"%s.%s\");\n" +
            "    %s.%s.overload(%s).implementation = function (){\n" +
            "        var originData = null;\n" +
            "        var modifyData = null;\n" +
            "        originData = Encode(arguments[0]);\n" +
            "        send({\"from\":\"jscode\",'payload':originData,'msg-type':'%s'});\n" +
            "        var op = recv('python_send',function(value){\n" +
            "            modifyData = value.payload;\n" +
            "        })\n" +
            "        op.wait();\n" +
            "        arguments[0] = Decode(modifyData);\n" +
            "        var rlt = %s.%s.overload(%s).apply(this, arguments);\n" +
            "        return rlt;\n" +
            "    }\n" +
            "})";
    public static final String fridaForwardCcodeTemplate="";
    public static final String fridaForwardOverloadCcodeTemplate="";
}
