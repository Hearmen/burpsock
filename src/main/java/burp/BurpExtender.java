package burp;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import net.razorvine.pickle.PickleException;
import net.razorvine.pyro.PyroException;
import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.fife.ui.rsyntaxtextarea.FileLocation;
import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rsyntaxtextarea.TextEditorPane;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.border.LineBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

public class BurpExtender implements IBurpExtender,ITab, ActionListener,IExtensionStateListener {

    public static final int PLATFORM_GENERIC = 0;
    public static final int PLATFORM_ANDROID = 1;
    public static final int PLATFORM_IOS = 2;
    public static final String EXTENSION = ".txt";

    public PrintWriter stdout;
    public PrintWriter stderr;
    public IExtensionHelpers hps;
    public IBurpExtenderCallbacks cbs;

    // global parameter
    private String pythonScript;
    private String pythonPath;
    private String tempFilePath;
    private PyroProxy pyroBridaService;
    private Process pyroServerProcess;
    private BufferedReader pyroStdOut;
    private BufferedReader pyroStdErr;
    private Thread stdoutThread;
    private Thread stderrThread;
    private Map<String,CustomHook> hookList;


    // global JObject
    public JPanel jPanelMain;
    public JPanel jPanelStartup;
    public JEditorPane jEditorPanelConsole;
    public JScrollPane jScrollPanelConsole;
    public JTextField jFieldForwardServerHost;
    public JTextField jFieldForwardServerPort;
    public TextEditorPane jEditorJavascript;
    public JTextField jFieldApplicationName;
    public StyleContext styleContext;
    public Style styleRed;
    public Style styleGreen;
    public JTextPane jTextServerStatus;
    public DefaultStyledDocument documentServerStatus;
    public JTextPane jTextApplicationStatus;
    public DefaultStyledDocument documentApplicationStatus;

    public JTextField jFieldHookMethodClass;
    public JTextField jFieldHookMethodName;
    public JTextField jFieldHookMethodArgument;
    public JRadioButton jRbtnSocket;
    public JRadioButton jRbtnNormal;
    public JRadioButton jRbtnSend;
    public JRadioButton jRbtnRecv;
    public JCheckBox jCboxIsIntercetor;

    public JPanel jPanelDefaultAndroidHooks;
    public JPanel jPanelDefaultGenericHooks;
    private JList<CustomHook> jListHookList;
    private DefaultListModel<CustomHook> listModelHookList;


    // controllable parameter
    public boolean bNeedServer;
    public boolean bServerStarted;
    public boolean bApplicationSpawned;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        callbacks.setExtensionName("Hello World Extension");
        callbacks.registerExtensionStateListener(this);

        this.hps = callbacks.getHelpers();
        this.cbs = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);

        this.stdout.println("hello burp!");
        this.stderr.println("hello burp!");

        // controllable parameter initiate
        bNeedServer = false;
        bServerStarted = false;
        bApplicationSpawned = false;

        // release core res
        // 在系统temp 目录下释放一些核心资源文件
        String[] bridaFiles = new String[] {
                "brida.js",
                "bridaServicePyro.py"
        };
        for(int i=0;i<bridaFiles.length;i++) {
            try {
                InputStream inputStream = getClass().getClassLoader().getResourceAsStream("res/" + bridaFiles[i]);
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                File outputFile = new File(System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + bridaFiles[i]);
                outputFile.delete();

                FileWriter fr = new FileWriter(outputFile);
                BufferedWriter br = new BufferedWriter(fr);

                String s;
                while ((s = reader.readLine()) != null) {
                    br.write(s);
                    br.newLine();
                }
                reader.close();
                br.close();

                // 保证数组的最后一个文件名是 Pyro4
                pythonScript = outputFile.getAbsolutePath();

            } catch (Exception e) {
                printException(e, "Error copying Pyro Server file");
            }
        }

        // Launch Pyro
        // 启动页面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                jPanelMain = new JPanel();
                jPanelMain.setLayout(new BoxLayout(jPanelMain,BoxLayout.Y_AXIS));

                jPanelStartup = new JPanel();
                jPanelStartup.setLayout(new BoxLayout(jPanelStartup,BoxLayout.Y_AXIS));

                // python path
                JPanel jPanelPythonPath = new JPanel();
                jPanelPythonPath.setLayout(new BoxLayout(jPanelPythonPath,BoxLayout.X_AXIS));
                jPanelPythonPath.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelPythonPath = new JLabel("Python binary path : ");
                JTextField jFieldPythonPath = new JTextField(200);
                jFieldPythonPath.setText("/opt/homebrew/bin/python3");
                pythonPath = jFieldPythonPath.getText().trim();
//                jFieldPythonPath.setText("C://python38/python3.exe");
                jFieldPythonPath.setMaximumSize(jFieldPythonPath.getPreferredSize());
                JButton jBtnPythonPath = new JButton("Select file");
                jBtnPythonPath.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        super.mouseClicked(e);
                        JFrame jFrameParent = new JFrame();
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setDialogTitle("Python Path");
                        int userSelection = fileChooser.showOpenDialog(jFrameParent);
                        if(userSelection == JFileChooser.APPROVE_OPTION){
                            final File pythonPathFile = fileChooser.getSelectedFile();
                            jFieldPythonPath.setText(pythonPathFile.getAbsolutePath());
                            pythonPath = pythonPathFile.getAbsolutePath();
                        }
                    }
                });
                jPanelPythonPath.add(jLabelPythonPath);
                jPanelPythonPath.add(jFieldPythonPath);
                jPanelPythonPath.add(jBtnPythonPath);

                // proxy host configure
                JPanel jPanelProxyServerHost = new JPanel();
                jPanelProxyServerHost.setLayout(new BoxLayout(jPanelProxyServerHost,BoxLayout.X_AXIS));
                jPanelProxyServerHost.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelProxyServerHost = new JLabel("Pyro Server Host :");
                JTextField jFieldProxyServerHost = new JTextField(200);
                jFieldProxyServerHost.setText("127.0.0.1");
                jFieldProxyServerHost.setMaximumSize(jFieldProxyServerHost.getPreferredSize());
                jPanelProxyServerHost.add(jLabelProxyServerHost);
                jPanelProxyServerHost.add(jFieldProxyServerHost);

                JPanel jPanelProxyServerPort = new JPanel();
                jPanelProxyServerPort.setLayout(new BoxLayout(jPanelProxyServerPort,BoxLayout.X_AXIS));
                jPanelProxyServerPort.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelProxyServerPort = new JLabel("Pyro Server Port :");
                JTextField jFieldProxyServerPort = new JTextField(200);
                jFieldProxyServerPort.setText("9999");
                jFieldProxyServerPort.setMaximumSize(jFieldProxyServerPort.getPreferredSize());
                jPanelProxyServerPort.add(jLabelProxyServerPort);
                jPanelProxyServerPort.add(jFieldProxyServerPort);

                JPanel JpanelTempFilePath = new JPanel();
                JpanelTempFilePath.setLayout(new BoxLayout(JpanelTempFilePath,BoxLayout.X_AXIS));
                JpanelTempFilePath.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelTempFilePath = new JLabel("Temp File Path :");
                JTextField jFieldTempFilePath = new JTextField(200);
                jFieldTempFilePath.setText(System.getProperty("java.io.tmpdir"));
                tempFilePath = jFieldTempFilePath.getText().trim();
                jFieldTempFilePath.setMaximumSize(jFieldTempFilePath.getPreferredSize());
                JButton jBtnTempFilePath = new JButton("Select file");
                jBtnTempFilePath.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        super.mouseClicked(e);
                        JFrame jFrameParent = new JFrame();
                        JFileChooser fileChooser = new JFileChooser();
                        fileChooser.setDialogTitle("Temp Path");
                        int userSelection = fileChooser.showOpenDialog(jFrameParent);
                        if(userSelection == JFileChooser.APPROVE_OPTION){
                            final File tempPathFile = fileChooser.getSelectedFile();
                            jFieldTempFilePath.setText(tempPathFile.getAbsolutePath());
                            tempFilePath = tempPathFile.getAbsolutePath();
                        }
                    }
                });
                JpanelTempFilePath.add(jLabelTempFilePath);
                JpanelTempFilePath.add(jFieldTempFilePath);
                JpanelTempFilePath.add(jBtnTempFilePath);


                JButton jBtnStart = new JButton("老司机,快点我!");
                jBtnStart.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e){
                        launchPyroServer(jFieldPythonPath.getText().trim(),pythonScript,jFieldProxyServerHost.getText().trim(),jFieldProxyServerPort.getText().trim());
//                        initExtender();
                    }
                });

                jEditorPanelConsole = new JEditorPane("text/html","<font color=\"green\"><b>***CONSOLE***</b></font><br/><br/>");
                jScrollPanelConsole = new JScrollPane(jEditorPanelConsole);
                jScrollPanelConsole.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                jEditorPanelConsole.setEditable(false);

                jPanelStartup.add(jPanelPythonPath);
                jPanelStartup.add(jPanelProxyServerHost);
                jPanelStartup.add(jPanelProxyServerPort);
                jPanelStartup.add(JpanelTempFilePath);
                jPanelStartup.add(jBtnStart);
                jPanelStartup.add(jScrollPanelConsole);

                jPanelMain.add(jPanelStartup);

                cbs.customizeUiComponent(jPanelMain);
                cbs.addSuiteTab(BurpExtender.this);
            }
        });
    }

    // Draw UI
    public void initExtender(){
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // UI

                printSuccessMessage("start draw extender");

                JSplitPane jPanelSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
                JSplitPane jPanelConsoleSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // Extension Tabs
                final JTabbedPane jPanelTabs = new JTabbedPane();
                jPanelTabs.addChangeListener(new ChangeListener() {
                    @Override
                    public void stateChanged(ChangeEvent e) {
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
//                                showHideButtons()
                            }
                        });
                    }
                });

                //*** Configure Tab ***
                JPanel jPanelConfiguration = new JPanel();
                jPanelConfiguration.setLayout(new BoxLayout(jPanelConfiguration,BoxLayout.Y_AXIS));

                // Panel style
                styleContext = new StyleContext();
                styleRed = styleContext.addStyle("red",null);
                StyleConstants.setForeground(styleRed, Color.RED);
                styleGreen = styleContext.addStyle("green",null);
                StyleConstants.setForeground(styleGreen, Color.GREEN);

                // host configure
                JPanel jPanelServerHost = new JPanel();
                jPanelServerHost.setLayout(new BoxLayout(jPanelServerHost,BoxLayout.X_AXIS));
                jPanelServerHost.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelServerHost = new JLabel("Transit Server Host :");
                jFieldForwardServerHost = new JTextField(200);
                jFieldForwardServerHost.setText("127.0.0.1");
                jFieldForwardServerHost.setMaximumSize(jFieldForwardServerHost.getPreferredSize());
                jPanelServerHost.add(jLabelServerHost);
                jPanelServerHost.add(jFieldForwardServerHost);

                JPanel jPanelServerPort = new JPanel();
                jPanelServerPort.setLayout(new BoxLayout(jPanelServerPort,BoxLayout.X_AXIS));
                jPanelServerPort.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelServerPort = new JLabel("Transit Server Port :");
                jFieldForwardServerPort = new JTextField(200);
                jFieldForwardServerPort.setText("8000");
                jFieldForwardServerPort.setMaximumSize(jFieldForwardServerPort.getPreferredSize());
                jPanelServerPort.add(jLabelServerPort);
                jPanelServerPort.add(jFieldForwardServerPort);

                // todo: fridaCompiler

                // todo: frida file

                // package name
                JPanel jPanelApplicationName = new JPanel();
                jPanelApplicationName.setLayout(new BoxLayout(jPanelApplicationName,BoxLayout.X_AXIS));
                jPanelApplicationName.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelApplicationName = new JLabel("Application package name : ");
                jFieldApplicationName = new JTextField(200);
                jFieldApplicationName.setText("com.huawei.myapplication");
                jFieldApplicationName.setMaximumSize(jFieldApplicationName.getPreferredSize());
                jPanelApplicationName.add(jLabelApplicationName);
                jPanelApplicationName.add(jFieldApplicationName);

                // todo: local or remote

                // todo : merger host and port
                jPanelConfiguration.add(jPanelServerHost);
                jPanelConfiguration.add(jPanelServerPort);
                jPanelConfiguration.add(jPanelApplicationName);

                // *** END Configure Tab***

                // *** Hook Function Tab ***
                JPanel jPanelHook = new JPanel();
                jPanelHook.setLayout(new BoxLayout(jPanelHook,BoxLayout.Y_AXIS));

                // custome hook panel
                JPanel jPanelCustomHook = new JPanel();
                jPanelCustomHook.setLayout(new BoxLayout(jPanelCustomHook,BoxLayout.Y_AXIS));

                JPanel jPanelHookMethodClass = new JPanel();
                jPanelHookMethodClass.setLayout(new BoxLayout(jPanelHookMethodClass, BoxLayout.X_AXIS));
                jPanelHookMethodClass.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelHookMethodClass = new JLabel("Class name: ");
                jFieldHookMethodClass = new JTextField(200);
                jFieldHookMethodClass.setMaximumSize( jFieldHookMethodClass.getPreferredSize() );
                jPanelHookMethodClass.add(jLabelHookMethodClass);
                jPanelHookMethodClass.add(jFieldHookMethodClass);

                JPanel jPanelHookMethodName = new JPanel();
                jPanelHookMethodName.setLayout(new BoxLayout(jPanelHookMethodName, BoxLayout.X_AXIS));
                jPanelHookMethodName.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelHookMethodName = new JLabel("Method name: ");
                jFieldHookMethodName = new JTextField(200);
                jFieldHookMethodName.setMaximumSize( jFieldHookMethodName.getPreferredSize() );
                jPanelHookMethodName.add(jLabelHookMethodName);
                jPanelHookMethodName.add(jFieldHookMethodName);
                // todo ： argument 根据 method 自动生成备选项
                JPanel jPanelHookMethodArgument = new JPanel();
                jPanelHookMethodArgument.setLayout(new BoxLayout(jPanelHookMethodArgument, BoxLayout.X_AXIS));
                jPanelHookMethodArgument.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelHookMethodArgument = new JLabel("Argument: ");
                jFieldHookMethodArgument = new JTextField(200);
                jFieldHookMethodArgument.setMaximumSize( jFieldHookMethodArgument.getPreferredSize() );
                jPanelHookMethodArgument.add(jLabelHookMethodArgument);
                jPanelHookMethodArgument.add(jFieldHookMethodArgument);

                // todo : argument encoder
                // 通过  modify 功能自己写去

                JPanel jPanelIsNeedServer = new JPanel();
                jPanelIsNeedServer.setLayout(new BoxLayout(jPanelIsNeedServer, BoxLayout.X_AXIS));
                jPanelIsNeedServer.setAlignmentX(Component.LEFT_ALIGNMENT);
                ButtonGroup btnGroupIsNeedServer = new ButtonGroup();
                JLabel jLabelIsForSocket = new JLabel("Is for Socket? : ");
                jRbtnSocket = new JRadioButton("Socket ");
                jRbtnNormal = new JRadioButton("Normal ");
                jRbtnSocket.setSelected(true);
                jRbtnNormal.setEnabled(false);
                btnGroupIsNeedServer.add(jRbtnSocket);
                btnGroupIsNeedServer.add(jRbtnNormal);
                ButtonGroup btnGroupSendOrRecv = new ButtonGroup();
                jRbtnSend = new JRadioButton("Send ");
                jRbtnRecv = new JRadioButton("Recv ");
                jRbtnSend.setSelected(true);
                JLabel jLabelSendOrRecv = new JLabel("Send Or Recv : ");
                btnGroupSendOrRecv.add(jRbtnSend);
                btnGroupSendOrRecv.add(jRbtnRecv);
                jCboxIsIntercetor = new JCheckBox("InterceptorHook",false);
                jPanelIsNeedServer.add(jLabelIsForSocket);
                jPanelIsNeedServer.add(jRbtnSocket);
                jPanelIsNeedServer.add(jRbtnNormal);
                jPanelIsNeedServer.add(jLabelSendOrRecv);
                jPanelIsNeedServer.add(jRbtnSend);
                jPanelIsNeedServer.add(jRbtnRecv);

                JButton JBtnAddHookMethod = new JButton("Add");
                JBtnAddHookMethod.setActionCommand("addHook");
                JBtnAddHookMethod.addActionListener(BurpExtender.this);

                jPanelCustomHook.add(jPanelHookMethodClass);
                jPanelCustomHook.add(jPanelHookMethodName);
                jPanelCustomHook.add(jPanelHookMethodArgument);
                jPanelCustomHook.add(jPanelIsNeedServer);
                jPanelCustomHook.add(jCboxIsIntercetor);
                jPanelCustomHook.add(JBtnAddHookMethod);

                // default hook panel
//                final JTabbedPane jPanelDefaultHooks = new JTabbedPane();
//
//                jPanelDefaultAndroidHooks = new JPanel();
//                jPanelDefaultAndroidHooks.setLayout(new BoxLayout(jPanelDefaultAndroidHooks, BoxLayout.Y_AXIS));
//
//                jPanelDefaultGenericHooks = new JPanel();
//                jPanelDefaultGenericHooks.setLayout(new BoxLayout(jPanelDefaultGenericHooks, BoxLayout.Y_AXIS));
//
//                // Initialize default hooks
//                initializeDefaultHooks();
//
//                jPanelDefaultHooks.add("Android",jPanelDefaultAndroidHooks);
//                jPanelDefaultHooks.add("Other",jPanelDefaultGenericHooks);

                // hook list
                hookList = new HashMap<String,CustomHook>();
                listModelHookList = new DefaultListModel<CustomHook>();
                JPanel jPanelHookList = new JPanel();
                jPanelHookList.setLayout(new BoxLayout(jPanelHookList, BoxLayout.X_AXIS));
                jPanelHookList.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelHookList = new JLabel("Hook list: ");
                jListHookList = new JList<CustomHook>(listModelHookList);
                JScrollPane jPanelHookListScroll = new JScrollPane(jListHookList);
                jPanelHookListScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                jPanelHookListScroll.setBorder(new LineBorder(Color.BLACK));
                jPanelHookListScroll.setMaximumSize( jPanelHookListScroll.getPreferredSize() );

                JPanel jPanelHookListButtons = new JPanel();
                jPanelHookListButtons.setLayout(new BoxLayout(jPanelHookListButtons, BoxLayout.Y_AXIS));
                JButton jBtnRemoveHook = new JButton("Remove");
                jBtnRemoveHook.setActionCommand("removeHook");
                jBtnRemoveHook.addActionListener(BurpExtender.this);
                JButton jBtnModifyHook = new JButton("Modify");
                jBtnModifyHook.setActionCommand("modifyHook");
                jBtnModifyHook.addActionListener(BurpExtender.this);
                jPanelHookListButtons.add(jBtnRemoveHook);
                jPanelHookListButtons.add(jBtnModifyHook);
                jPanelHookList.add(jLabelHookList);
                jPanelHookList.add(jPanelHookListScroll);
                jPanelHookList.add(jPanelHookListButtons);

                jPanelHook.add(jPanelCustomHook);
//                jPanelHook.add(jPanelDefaultHooks);
                jPanelHook.add(jPanelHookList);

                // *** Hook Function Tab ***

                // *** JS EDITOR PANEL TAB ***
                jEditorJavascript = new TextEditorPane();
                jEditorJavascript.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
                jEditorJavascript.setCodeFoldingEnabled(false);
                RTextScrollPane jPanelScriptEditor = new RTextScrollPane(jEditorJavascript);
                jEditorJavascript.setFocusable(true);
                // *** END JS EDITOR PANEL TAB ***

                jPanelTabs.add("Configuration",jPanelConfiguration);
                jPanelTabs.add("Custom Hook",jPanelHook);
                jPanelTabs.add("JS Editor",jPanelScriptEditor);

                // RIGHT BUTTONs PANEL
                JPanel jPanelRightSplit = new JPanel();
                jPanelRightSplit.setLayout(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;

                // server status
                JPanel jPanelServerStatus = new JPanel();
                jPanelServerStatus.setLayout(new BoxLayout(jPanelServerStatus,BoxLayout.X_AXIS));
                jPanelServerStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelServerStatus = new JLabel("Server status : ");
                documentServerStatus = new DefaultStyledDocument();
                jTextServerStatus = new JTextPane(documentServerStatus);
                try {
                    documentServerStatus.insertString(0,"Not running",styleRed);
                } catch (BadLocationException e) {
                    e.printStackTrace();
                }
                jTextServerStatus.setMaximumSize(jTextServerStatus.getPreferredSize());
                jPanelServerStatus.add(jLabelServerStatus);
                jPanelServerStatus.add(jTextServerStatus);

                // application status
                JPanel jPanelApplicationStatus = new JPanel();
                jPanelApplicationStatus.setLayout(new BoxLayout(jPanelApplicationStatus,BoxLayout.X_AXIS));
                jPanelApplicationStatus.setAlignmentX(Component.LEFT_ALIGNMENT);
                JLabel jLabelApplicationStatus = new JLabel("Application status :");
                documentApplicationStatus = new DefaultStyledDocument();
                jTextApplicationStatus = new JTextPane(documentApplicationStatus);
                try {
                    documentApplicationStatus.insertString(0,"Not hooked",styleRed);
                } catch (BadLocationException e) {
                    e.printStackTrace();
                }
                jTextApplicationStatus.setMaximumSize(jTextApplicationStatus.getPreferredSize());
                jPanelApplicationStatus.add(jLabelApplicationStatus);
                jPanelApplicationStatus.add(jTextApplicationStatus);

                JButton jBtnStartServer = new JButton("Start Server");
                jBtnStartServer.setActionCommand("startServer");
                jBtnStartServer.addActionListener(BurpExtender.this);

                JButton jBtnStopServer = new JButton("Stop Server");
                jBtnStopServer.setActionCommand("stopServer");
                jBtnStopServer.addActionListener(BurpExtender.this);

                JButton jBtnSpawnApplication = new JButton("Spawn application");
                jBtnSpawnApplication.setActionCommand("spawnApplication");
                jBtnSpawnApplication.addActionListener(BurpExtender.this);

                JButton jBtnAttachApplication = new JButton("Attach application");
                jBtnAttachApplication.setActionCommand("attachApplication");
                jBtnAttachApplication.addActionListener(BurpExtender.this);

                JButton jBtnKillApplication = new JButton("Kill application");
                jBtnKillApplication.setActionCommand("killApplication");
                jBtnKillApplication.addActionListener(BurpExtender.this);

                JButton jBtnDetachApplication = new JButton("Detach application");
                jBtnDetachApplication.setActionCommand("detachApplication");
                jBtnDetachApplication.addActionListener(BurpExtender.this);

                JButton jBtnReloadHoodks = new JButton("Reload Hooks");
                jBtnReloadHoodks.setActionCommand("reloadHooks");
                jBtnReloadHoodks.addActionListener(BurpExtender.this);

                JButton jBtnClearConsole = new JButton("Clear console");
                jBtnClearConsole.setActionCommand("clearConsole");
                jBtnClearConsole.addActionListener(BurpExtender.this);

                JSeparator jSeparator = new JSeparator(SwingConstants.HORIZONTAL);
                jSeparator.setBorder(BorderFactory.createMatteBorder(3, 0, 3, 0, Color.ORANGE));

                JButton jBtnSaveSettingsToFile = new JButton("Save settings to file");
                jBtnSaveSettingsToFile.setActionCommand("saveSettingsToFile");
                jBtnSaveSettingsToFile.addActionListener(BurpExtender.this);

                JButton jBtnLoadSettingsFromFile = new JButton("Load settings from file");
                jBtnLoadSettingsFromFile.setActionCommand("loadSettingsFromFile");
                jBtnLoadSettingsFromFile.addActionListener(BurpExtender.this);

                jPanelRightSplit.add(jPanelServerStatus,gbc);
                jPanelRightSplit.add(jPanelApplicationStatus,gbc);
                jPanelRightSplit.add(jBtnStartServer,gbc);
                jPanelRightSplit.add(jBtnStopServer,gbc);
                jPanelRightSplit.add(jBtnSpawnApplication,gbc);
                jPanelRightSplit.add(jBtnAttachApplication,gbc);
                jPanelRightSplit.add(jBtnKillApplication,gbc);
                jPanelRightSplit.add(jBtnDetachApplication,gbc);
                jPanelRightSplit.add(jSeparator,gbc);
                jPanelRightSplit.add(jBtnSaveSettingsToFile,gbc);
                jPanelRightSplit.add(jBtnLoadSettingsFromFile,gbc);

                jPanelSplit.setLeftComponent(jPanelTabs);
                jPanelSplit.setRightComponent(jPanelRightSplit);
                jPanelSplit.setResizeWeight(.9d);

                // BOTTOM CONOSLE PANEL
                jEditorPanelConsole = new JEditorPane("text/html","<font color=\"green\"><b>***CONSOLE***</b></font><br/><br/>");
                jScrollPanelConsole = new JScrollPane(jEditorPanelConsole);
                jScrollPanelConsole.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
                jEditorPanelConsole.setEditable(false);

                jPanelConsoleSplit.setTopComponent(jPanelSplit);
                jPanelConsoleSplit.setBottomComponent(jScrollPanelConsole);
                jPanelConsoleSplit.setResizeWeight(.7d);

                jPanelMain.remove(jPanelStartup);
                jPanelMain.add(jPanelConsoleSplit);

                printSuccessMessage("start up correct");
                jPanelMain.updateUI();

            }
        });
    }

    public void launchPyroServer(String pythonPath,String pythonScript, String pyroHost, String pyroPort){
        Runtime rt = Runtime.getRuntime();

        String[] startServerCommand;
        String[] execEnv;
        String debugCommandToPrint;

        // todo : virtual ENV ???
        startServerCommand = new String[]{pythonPath,"-i",pythonScript,pyroHost.trim(),pyroPort.trim()};
        execEnv = null;

        debugCommandToPrint = "\"" + pythonPath + "\" -i \"" + pythonScript + "\" " + pyroHost.trim() + " " + pyroPort.trim();
        printSuccessMessage("Start Pyro server command: " + debugCommandToPrint);

        try{
            pyroServerProcess = rt.exec(startServerCommand,execEnv);

            pyroStdOut = new BufferedReader(new InputStreamReader(pyroServerProcess.getInputStream()));
            pyroStdErr = new BufferedReader(new InputStreamReader(pyroServerProcess.getErrorStream()));

            // Initialize thread that will read stdout
            stdoutThread = new Thread() {
                public void run() {
                    while(true) {
                        try {
                            final String line = pyroStdOut.readLine();
                            // Only used to handle Pyro first message (when server start)
                            if(line.equals("Ready.")) {
                                pyroBridaService = new PyroProxy(new PyroURI("PYRO:BridaServicePyro@" + pyroHost.trim() + ":" + pyroPort.trim()));
                                initExtender();
                                printSuccessMessage("Pyro server started correctly");
                                // Standard line
                            } else {
                                printSuccessMessage(line);
                            }
                        } catch (IOException e) {
                            printException(e,"Error reading Pyro stdout");
                        }
                    }
                }
            };
            stdoutThread.start();

            // Initialize thread that will read stderr
            stderrThread = new Thread() {
                public void run() {
                    while(true) {
                        try {
                            final String line = pyroStdErr.readLine();
                            printFailureMessage(line);
                        } catch (IOException e) {
                            printException(e,"Error reading Pyro stderr");
                        }
                    }
                }

            };
            stderrThread.start();

        } catch (Exception e){
            printException(e, "Exception starting Pyro server");
        }

    }

    public static Object executePyroCall(PyroProxy pyroBridaService, String name, Object[] arguments) throws Exception {

        final ArrayList<Object> threadReturn = new ArrayList<Object>();

        final Runnable stuffToDo = new Thread()  {
            @Override
            public void run() {
                try {
                    threadReturn.add(pyroBridaService.call(name, arguments));
                } catch (PickleException | PyroException | IOException e) {
                    threadReturn.add(e);
                }
            }
        };

        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final Future future = executor.submit(stuffToDo);
        executor.shutdown();

        try {
            //future.get(1, TimeUnit.MINUTES);
            future.get(30, TimeUnit.SECONDS);
        }
        catch (InterruptedException | ExecutionException | TimeoutException ie) {
            threadReturn.add(ie);
        }

        if (!executor.isTerminated())
            executor.shutdownNow();

        if(threadReturn.size() > 0) {
            if(threadReturn.get(0) instanceof Exception) {
                throw (Exception)threadReturn.get(0);
            } else {
                return threadReturn.get(0);
            }
        } else {
            return null;
        }

    }

    // default hook and trace
    private void execute_startup_scripts() {}

    // 每次 启动进程时生成 generated.js 文件
    public void spawnApplication(boolean spawn){
        try{
            // todo : device type
            String device = "usb";

            if(!generateFridaJsFile()){
                printFailureMessage("generate firda js file failed");
            }
            printSuccessMessage("generate frida js file success");

            if(spawn){
                printSuccessMessage("start spawn ");
                boolean bResult = (boolean)executePyroCall(pyroBridaService, "spawn_application",new Object[] {jFieldApplicationName.getText().trim(), tempFilePath + System.getProperty("file.separator") + "GeneratedOutput.js",device});

                if(bResult)
                    printSuccessMessage("spawn application sueccess");
                else {
                    executePyroCall(pyroBridaService, "disconnect_application",new Object[] {});
                    printFailureMessage("spawn application suecces failed");
                    return;
                }
                execute_startup_scripts();

                bResult = (boolean)executePyroCall(pyroBridaService, "resume_application", new Object[] {});
            } else {
                printSuccessMessage("start attach");
                boolean bResult = (boolean)executePyroCall(pyroBridaService, "attach_application",new Object[] {jFieldApplicationName.getText().trim(), tempFilePath + System.getProperty("file.separator") + "GeneratedOutput.js",device});
                if(bResult)
                    printSuccessMessage("attach application sueccess");
                else {
                    executePyroCall(pyroBridaService, "detach_application",new Object[] {});
                    printFailureMessage("attach application suecces failed");
                    return;
                }

                execute_startup_scripts();
            }

            bApplicationSpawned = true;

            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {

                    jTextApplicationStatus.setText("");
                    try {
                        documentApplicationStatus.insertString(0,"Hooking",styleGreen);
                    } catch (BadLocationException e) {
                        printException(e,"Exception setting labels");
                    }
                }
            });

        } catch (Exception e){
            e.printStackTrace();
            printException(e, "spwan application failed");
        }
    }

    public void killApplication(){
        try {
            executePyroCall(pyroBridaService, "disconnect_application",new Object[] {});
            bApplicationSpawned = false;
            SwingUtilities.invokeLater(new Runnable() {

                @Override
                public void run() {
                    jTextApplicationStatus.setText("");
                    try {
                        documentApplicationStatus.insertString(0, "NOT hooked", styleRed);
                    } catch (BadLocationException e) {
                        printException(e,"Exception setting labels");
                    }
                }
            });
            printSuccessMessage("Killing application executed");
        } catch (final Exception e) {
            printException(e,"Exception killing application");
        }
    }

    public void detachApplication(){
        try {
            executePyroCall(pyroBridaService, "detach_application",new Object[] {});
            bApplicationSpawned = false;
            SwingUtilities.invokeLater(new Runnable() {

                @Override
                public void run() {
                    jTextApplicationStatus.setText("");
                    try {
                        documentApplicationStatus.insertString(0, "NOT hooked", styleRed);
                    } catch (BadLocationException e) {
                        printException(e,"Exception setting labels");
                    }
                }
            });
            printSuccessMessage("Killing application executed");
        } catch (final Exception e) {
            printException(e,"Exception killing application");
        }
    }

    public boolean generateFridaJsFile(){
        try {
            File outputFile = new File(tempFilePath + System.getProperty("file.separator") + "GeneratedOutput.js");
            FileWriter fr = new FileWriter(outputFile);
            BufferedWriter br  = new BufferedWriter(fr);
            BufferedReader in = new BufferedReader(new FileReader(System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + "brida.js"));
            String str;
            while ((str = in.readLine()) != null) {
                br.write(str);
                br.newLine();
            }
            in.close();

            for(String hookName : hookList.keySet()){
                CustomHook customHook = hookList.get(hookName);
                in = new BufferedReader(new FileReader(tempFilePath + System.getProperty("file.separator") + customHook.toString()+EXTENSION));
                br.write("//"+customHook.toString());
                br.newLine();
                while ((str = in.readLine()) != null) {
                    br.write(str);
                    br.newLine();
                }
                in.close();
            }
            br.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public void startServer(String forwardServerHost, String forwardServerPort){
        if(pyroBridaService != null && !bServerStarted){
            try {
                boolean bResult = (boolean)executePyroCall(pyroBridaService,"launch_server",new Object[] {forwardServerHost,forwardServerPort});
                if(bResult){
                    bServerStarted = true;
                    executePyroCall(pyroBridaService,"set_proxy",new Object[] {"{\"http\": \"http://127.0.0.1:8080\"}"});
                    SwingUtilities.invokeLater(new Runnable() {

                        @Override
                        public void run() {
                            jTextServerStatus.setText("");
                            try {
                                documentServerStatus.insertString(0,"Server running",styleGreen);
                            } catch (BadLocationException e) {
                                printException(e,"Exception setting labels");
                            }
                        }
                    });
                }
            } catch (Exception e) {
                printException(e,"launch_server error");
            }
        }
    }

    public void stopServer(){
        if(pyroBridaService != null && bServerStarted){
            try {
                boolean bResult = (boolean)executePyroCall(pyroBridaService,"stop_server",new Object[] {});
                if(bResult){
                    bServerStarted = false;
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            jTextServerStatus.setText("");
                            try {
                                documentServerStatus.insertString(0,"Not running",styleRed);
                            } catch (BadLocationException e) {
                                printException(e,"Exception setting labels");
                            }
                        }
                    });
                }
            } catch (Exception e) {
                printException(e,"launch_server error");
            }
        }
    }

    // 针对每个函数生成一个文件
    public CustomHook addHook(String packageName, String className, int os, String methodName, String[] parameters, List<CustomHook> parametersEncoder, boolean isNeedForwardServer, boolean sendOrRecv, boolean isInterceptorHook) {

        CustomHook customHook = new CustomHook(packageName, className, PLATFORM_ANDROID,methodName, parameters, parametersEncoder, isNeedForwardServer, sendOrRecv, isInterceptorHook);
        String hookName = customHook.toString();
        printSuccessMessage("add hook : "+customHook.toJSON());
        hookList.put(hookName,customHook);
        String firdaScript = generateFridaCode(customHook);
        if(firdaScript==null){
            printFailureMessage("generate frida js error");
            return null;
        }
        try {
            File outputFile = new File(tempFilePath + System.getProperty("file.separator") + hookName +EXTENSION);
            FileWriter fr = new FileWriter(outputFile);
            BufferedWriter br  = new BufferedWriter(fr);
            br.write(firdaScript);
            br.close();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return customHook;
    }

    public String generateFridaCode(CustomHook customHook){
        String fridaJsHook = null;
        try {
            boolean isNeedForwardServer = customHook.isNeedForwardServer();
            boolean isIntercetorHook = customHook.isInterceptorHook();
            String sendOrRecv = customHook.getSendOrRecv()?"msg_to":"msg_from";
            String packageName = customHook.getPackageName();
            String className = customHook.getClassName();
            String methodName = customHook.getMethodName();
            String[] parameters = customHook.getParameters();
            List<CustomHook> parameterEncoder = customHook.getParameterEncoders();

            if(isNeedForwardServer){
                if( parameters==null) {
                    fridaJsHook = String.format(FridaTemplate.fridaForwardTemplate, className, packageName, className, className, methodName, sendOrRecv, className, methodName);
                }
                else{
                    fridaJsHook = String.format(FridaTemplate.fridaForwardOverloadTemplate, className, packageName, className, className, methodName, String.join(",", parameters),sendOrRecv, className, methodName,String.join(",", parameters));
                }
            }else{
                if( parameters==null) {
                    fridaJsHook = String.format(FridaTemplate.fridaNormalTemplate, className, packageName, className, className, methodName, className, methodName, className, methodName);
                }
                else{
                    fridaJsHook = String.format(FridaTemplate.fridaOverloadTemplate, className, packageName, className, className, methodName,String.join(",", parameters), className, methodName, className, methodName,String.join(",", parameters));
                }
            }

        } catch (Exception e) {
            printException(e,"generate frida js Failed");
        }
        return fridaJsHook;
    }

    public boolean removeHook(CustomHook customHook){
        File toDelFile = new File(tempFilePath + System.getProperty("file.separator") + customHook.toString()+EXTENSION);
        if(toDelFile.delete()){
            hookList.remove(customHook.toString());
            printSuccessMessage(String.format("delete hook %s success!",toDelFile.getAbsolutePath()));
            return true;
        }else{
            printFailureMessage(String.format("delete hook %s failed!",toDelFile.getAbsolutePath()));
            return false;
        }
    }

    public boolean modifyhook(CustomHook customHook){
        //
        return true;
    }

    private void exportConfigurationsToFile() {
        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Configuration output file");
        int userSelection = fileChooser.showSaveDialog(parentFrame);
        if(userSelection == JFileChooser.APPROVE_OPTION) {
            File outputFile = fileChooser.getSelectedFile();
            // Check if file already exists
            if(outputFile.exists()) {
                JFrame parentDialogResult = new JFrame();
                int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "The file already exists. Would you like to overwrite it?","Warning",JOptionPane.YES_NO_OPTION);
                if(dialogResult != JOptionPane.YES_OPTION){
                    return;
                }
            }
            FileWriter fw;
            try {
                fw = new FileWriter(outputFile);
                JSONObject object = new JSONObject();
                object.put("serverHost",jFieldForwardServerHost.getText().trim());
                object.put("serverPort",jFieldForwardServerPort.getText().trim());
                object.put("applicationName",jFieldApplicationName.getText().trim());
                JSONArray hooks = new JSONArray();
                for(String hookName : hookList.keySet()){
                    JSONObject hook = new JSONObject();
                    CustomHook customHook = hookList.get(hookName);
                    hook.put("customHook",customHook.toJSON());
                    File fridajsFile = new File(tempFilePath + System.getProperty("file.separator") + customHook.toString()+EXTENSION);
                    BufferedReader br = new BufferedReader(new FileReader(fridajsFile));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                        sb.append(System.lineSeparator());
                    }
                    br.close();
                    hook.put("hookContent",sb.toString());
                    hooks.add(hook);
                }
                object.put("hooks",hooks);
                fw.write(object.toJSONString());
                fw.close();
                printSuccessMessage("Saving configurations to file executed correctly");
            } catch (Exception e) {
                printException(e,"Exception exporting configurations to file");
                return;
            }
        }
    }

    private void loadConfigurationsFromFile() {

        JFrame parentFrame = new JFrame();
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Configuration input file");
        int userSelection = fileChooser.showOpenDialog(parentFrame);
        if(userSelection == JFileChooser.APPROVE_OPTION) {
            File inputFile = fileChooser.getSelectedFile();
            try {
                BufferedReader br = new BufferedReader(new FileReader(inputFile));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                }
                br.close();
                JSONObject object = JSON.parseObject(sb.toString());
                jFieldForwardServerHost.setText(object.get("serverHost").toString());
                jFieldForwardServerPort.setText(object.get("serverPort").toString());
                jFieldApplicationName.setText(object.get("applicationName").toString());
                JSONArray array= object.getJSONArray("hooks");
                // 选择是否覆盖已有 hook
                if (array.size() > 0){
                    printSuccessMessage("choosing");
                    JFrame parentDialogResult = new JFrame();
                    int dialogResult = JOptionPane.showConfirmDialog(parentDialogResult, "Do you want to override the current hooks","Warning",JOptionPane.YES_NO_OPTION);
                    if(dialogResult == JOptionPane.YES_OPTION){
                        clearHooks();
                    }
                }
                Iterator<Object> it   = array.iterator();
                while (it.hasNext()) {
                    JSONObject jsonObj = (JSONObject) it.next();
                    String customHookJSON = jsonObj.getString("customHook");
                    CustomHook customHook = CustomHook.fromJSON(customHookJSON);
                    String hookContent = jsonObj.getString("hookContent");
                    File outputFile = new File(System.getProperty("java.io.tmpdir") + System.getProperty("file.separator") + customHook+ EXTENSION);
                    FileWriter fr = new FileWriter(outputFile);
                    BufferedWriter bw = new BufferedWriter(fr);
                    bw.write(hookContent);
                    bw.close();
                    listModelHookList.addElement(customHook);
                    hookList.put(customHook.toString(),customHook);
                }

            } catch (Exception e) {
                e.printStackTrace();
                printException(e,"error");
            }
        }
    }

    private void reloadHooks(){
        try {
            executePyroCall(pyroBridaService, "reload_script",new Object[] {});
            printSuccessMessage("Reloading script executed");
        } catch (final Exception e) {
            printException(e,"Exception reloading script");
        }
    }

    private void clearConsole(){
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                String newConsoleText = "<font color=\"green\">";
                newConsoleText = newConsoleText + "<b>**** Console cleared successfully ****</b><br/>";
                newConsoleText = newConsoleText + "</font><br/>";
                jEditorPanelConsole.setText(newConsoleText);
            }
        });
    }

    private void clearHooks(){
        // 删除临时目录中的 hook
        for(String hookName : hookList.keySet()){
            CustomHook customHook = hookList.get(hookName);
            File fw = new File(tempFilePath + System.getProperty("file.separator") + customHook.toString()+EXTENSION);
            fw.delete();
        }
        hookList.clear();
    }

    @Override
    public String getTabCaption() {
        // tab 标签
        return "BurpSock";
    }

    @Override
    public Component getUiComponent() {
        // tab 内容
        return jPanelMain;
    }

    @Override
    public void actionPerformed(ActionEvent event) {
        String command = event.getActionCommand();
        if(command.equals("addHook")){

            String className = jFieldHookMethodClass.getText();
            String methodName = jFieldHookMethodName.getText();
            String methodArgument = jFieldHookMethodArgument.getText();
            String[] methodArguments;

            if(className.length()==0){
                printFailureMessage("Class Name must have value");
                return;
            }
            if(methodName.length()==0) {
                printFailureMessage("Method Name must have value");
                return;
            }
            if(methodArgument.length()==0){
                methodArguments = null;
            }else{
                if(methodArgument.startsWith("(") && methodArgument.endsWith(")")) {
                    methodArguments = methodArgument.substring(1,methodArgument.length()-1).trim().split(",");
                    printSuccessMessage(String.join(",",methodArguments));
                }
                else{
                    printFailureMessage("Argument value must be surrounded by ()");
                    return;
                }
            }

            int nameSperator = className.lastIndexOf(".");
            String packageName = className.substring(0,nameSperator);
            className = className.substring(nameSperator+1);

            boolean isNeedForwardServer = jRbtnSocket.isSelected();
            //jRbtnNormal;
            boolean isSendOrRecv = jRbtnSend.isSelected();
            boolean isInterceptorHook = jCboxIsIntercetor.isSelected();

            CustomHook customHook = addHook(packageName, className, PLATFORM_ANDROID,methodName, methodArguments, null, isNeedForwardServer, isSendOrRecv, isInterceptorHook);

            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    listModelHookList.addElement(customHook);
                    jFieldHookMethodClass.setText("");
                    jFieldHookMethodName.setText("");
                    jFieldHookMethodArgument.setText("");
                    jCboxIsIntercetor.setSelected(false);
                }
            });
        } else if(command.equals("removeHook")){
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    int index = jListHookList.getSelectedIndex();
                    if(index != -1) {
                        CustomHook customHook = listModelHookList.getElementAt(index);
                        if(removeHook(customHook))
                            listModelHookList.remove(index);
                    }
                }
            });
        } else if(command.equals("modifyHook")){
            int index = jListHookList.getSelectedIndex();
            if(index != -1) {
                CustomHook customHook = (CustomHook)jListHookList.getSelectedValue();
                try {
                    File fridajsFile = new File(tempFilePath + System.getProperty("file.separator") + customHook.toString()+EXTENSION);
//                    final FileLocation fl = FileLocation.create(fridajsFile);
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            Desktop desktop = Desktop.getDesktop();
                            try {
                                printSuccessMessage(fridajsFile.getAbsolutePath());
                                desktop.open(fridajsFile);
                            } catch (IOException e) {
                                e.printStackTrace();
                                printException(e,"open file error");
                            }
//                            try {
//                                jEditorJavascript.load(fl,null);
//                            } catch (IOException e) {
//                                printException(e,"Exception loading JS file");
//                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } else if(command.equals("startServer") && !bServerStarted){
            startServer(jFieldForwardServerHost.getText().trim(),jFieldForwardServerPort.getText().trim());
        }else if(command.equals("stopServer") && bServerStarted){
            stopServer();
        }else if((command.equals("spawnApplication") && !bNeedServer) ||(command.equals("spawnApplication") && bNeedServer && bServerStarted)){
            spawnApplication(true);
        }else if((command.equals("attachApplication") && !bNeedServer) ||(command.equals("attachApplication") && bNeedServer && bServerStarted)){
            spawnApplication(false);
        }else if(command.equals("killApplication") && bApplicationSpawned) {
            killApplication();
        }else if(command.equals("detachApplication") && bApplicationSpawned) {
            detachApplication();
        }else if(command.equals("reloadHooks") && bApplicationSpawned) {
            reloadHooks();
        }else if(command.equals("clearConsole") && bApplicationSpawned) {
            clearConsole();
        }else if(command.equals("saveSettingsToFile")) {
            exportConfigurationsToFile();
        } else if(command.equals("loadSettingsFromFile")) {
            loadConfigurationsFromFile();
        }
    }

    @Override
    public void extensionUnloaded() {
        // 停止 transit server
        if(bServerStarted){
            try {
                executePyroCall(pyroBridaService, "stopServer", new Object[] {});
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        clearHooks();

        // 停止 RPC 服务
        if(pyroBridaService != null) {
            stdoutThread.stop();
            stderrThread.stop();
            try {
                //pyroBridaService.call("shutdown");
                executePyroCall(pyroBridaService, "shutdown", new Object[] {});
                pyroServerProcess.destroy();
                pyroBridaService.close();

                printSuccessMessage("Pyro server shutted down");

            } catch (final Exception e) {

                printException(e,"Exception shutting down Pyro server");

            }

        }

    }


    public void printException(Exception e,String message){
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    String oldConsoleText = jEditorPanelConsole.getText();
                    Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
                    Matcher m = p.matcher(oldConsoleText);
                    String newConsoleText = "";
                    if(m.find()) {
                        newConsoleText = m.group(1);
                    }
                    newConsoleText = newConsoleText + "<font color=\"red\">";
                    newConsoleText = newConsoleText + "<b>" + message + "</b><br/>";
                    if(e != null) {
                        newConsoleText = newConsoleText + e.toString() + "<br/>";
                        //consoleText = consoleText + e.getMessage() + "<br/>";
                        StackTraceElement[] exceptionElements = e.getStackTrace();
                        for(int i=0; i< exceptionElements.length; i++) {
                            newConsoleText = newConsoleText + exceptionElements[i].toString() + "<br/>";
                        }
                    }
                    newConsoleText = newConsoleText + "</font>";
                    jEditorPanelConsole.setText(newConsoleText);
                }
            });
    }

    public void printFailureMessage(String message){
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                String oldConsoleText = jEditorPanelConsole.getText();
                Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
                Matcher m = p.matcher(oldConsoleText);
                String newConsoleText = "";
                if(m.find()) {
                    newConsoleText = m.group(1);
                }
                newConsoleText = newConsoleText + "<font color=\"red\">";
                newConsoleText = newConsoleText + "<b>" + message + "</b><br/>";
                newConsoleText = newConsoleText + "</font>";
                jEditorPanelConsole.setText(newConsoleText);
            }
        });
    }

    public void printSuccessMessage(String message){
        //this.stdout.println(message);
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                String oldConsoleText = jEditorPanelConsole.getText();
                Pattern p = Pattern.compile("^.*<body>(.*)</body>.*$", Pattern.DOTALL);
                Matcher m = p.matcher(oldConsoleText);
                String newConsoleText = "";
                if(m.find()) {
                    newConsoleText = m.group(1);
                }
                newConsoleText = newConsoleText + "<font color=\"green\">";
                newConsoleText = newConsoleText + "<b>" + message + "</b><br/>";
                newConsoleText = newConsoleText + "</font>";
                jEditorPanelConsole.setText(newConsoleText);
            }
        });
    }

    protected enum Transformation {
        GZIP {
            public String toString() { return "GZIP"; }
            protected OutputStream getCompressor(OutputStream os) throws IOException {
                return new GZIPOutputStream(os);
            }
            protected InputStream getDecompressor(InputStream is) throws IOException {
                return new GZIPInputStream(is);
            }
        },
        ZLIB {
            public String toString() { return "ZLIB"; }
            protected OutputStream getCompressor(OutputStream os) throws IOException {
                return new DeflaterOutputStream(os);
            }
            protected InputStream getDecompressor(InputStream is) throws IOException {
                return new InflaterInputStream(is);
            }
        },
        BASE64 {
            public String toString() { return "Base64"; }
            public byte[] encode(byte[] input) throws IOException { return Base64.encodeBase64(input); }
            public byte[] decode(byte[] input) throws IOException { return Base64.decodeBase64(input); }
        },
        BASE64_URL_SAFE {
            public String toString() { return "Base64 URLsafe"; }
            public byte[] encode(byte[] input) throws IOException { return Base64.encodeBase64URLSafe(input); }
            public byte[] decode(byte[] input) throws IOException { return Base64.decodeBase64(input); }
        },
        ASCII_HEX {
            public String toString() { return "ASCII-HEX"; }
            public byte[] encode(byte[] input) throws IOException { return hex.encode(input); }
            public byte[] decode(byte[] input) throws IOException, DecoderException { return hex.decode(input); }
            private Hex hex = new Hex("ASCII");
        },
        URL_ENCODING {
            public String toString() { return "URL"; }
            public byte[] encode(byte[] input) throws IOException {
                return URLEncoder.encode(new String(input, "ISO-8859-1"), "ISO-8859-1").getBytes();
            }
            public byte[] decode(byte[] input) throws IOException {
                return URLDecoder.decode(new String(input, "ISO-8859-1"), "ISO-8859-1").getBytes();
            }
        };

        protected OutputStream getCompressor(OutputStream os) throws IOException { return null; }
        protected InputStream getDecompressor(InputStream is) throws IOException { return null; }
        public byte[] encode(byte[] input) throws IOException {
            ByteArrayOutputStream outbytes = new ByteArrayOutputStream(input.length);
            OutputStream comp = getCompressor(outbytes);
            comp.write(input);
            comp.close();
            return outbytes.toByteArray();
        }
        public byte[] decode(byte[] input) throws IOException,DecoderException {
            ByteArrayOutputStream outbytes = new ByteArrayOutputStream();
            ByteArrayInputStream inbytes =  new ByteArrayInputStream(input);
            InputStream comp = getDecompressor(inbytes);
            int len;
            byte[] buffer = new byte[1024];
            while ((len = comp.read(buffer)) > 0) {
                outbytes.write(buffer, 0, len);
            }
            comp.close();
            inbytes.close();
            return outbytes.toByteArray();
        }
    }

    public JPanel addButtonToHooksAndFunctions(DefaultHook dh) {
        JLabel tempHookLabel = new JLabel(dh.getName());
        JPanel lineJPanel = new JPanel();
        lineJPanel.setLayout(new BoxLayout(lineJPanel, BoxLayout.X_AXIS));
        lineJPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        if(dh.isInterceptorHook()) {
            final JToggleButton tempHookToggleButton = new JToggleButton("Enable",false);
            tempHookToggleButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent actionEvent) {
                    // Enabling hook
                    if(tempHookToggleButton.isSelected()) {
                        if(bApplicationSpawned) {
                            // Call hook
                            try {
                                //pyroBridaService.call("callexportfunction",dh.getFridaExportName(),new String[0]);
                                executePyroCall(pyroBridaService, "callexportfunction",new Object[] {dh.getFridaExportName(),new String[0]});
                                printSuccessMessage("Hook " + dh.getName() + " ENABLED");
                                dh.setEnabled(true);
                            } catch (Exception e) {
                                printException(e,"Error while enabling hook " + dh.getName());
                            }
                        } else {
                            printSuccessMessage("Hook " + dh.getName() + " ENABLED");
                            dh.setEnabled(true);
                        }
                        // Disabling hook
                    } else {
                        if(bApplicationSpawned) {
                            printException(null,"It is not possible to detach a single hook while app is running (you can detach ALL the hooks with the \"Detach all\" button)");
                            tempHookToggleButton.setSelected(true);
                        } else {
                            printSuccessMessage("Hook " + dh.getName() + " DISABLED");
                            dh.setEnabled(false);
                        }
                    }
                }
            });
            lineJPanel.add(tempHookToggleButton);
        } else {
            JButton tempHookButton = new JButton("Execute");
            tempHookButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent actionEvent) {
                    if(bApplicationSpawned) {
                        // Parameters
                        String[] currentParameters;
                        if(dh.isPopupParameters()) {
                            String parametersPopup = JOptionPane.showInputDialog("Enter parameter(s), delimited by \"#,#\"");
                            currentParameters = parametersPopup.split("#,#");
                        } else {
                            // For cases different from POPUP parameters are already encoded
                            currentParameters = dh.getParameters();
                        }
                        // Call exported function
                        try {
                            printSuccessMessage("*** Output " + dh.getName() + ":");
                            //String ret = (String)pyroBridaService.call("callexportfunction",dh.getFridaExportName(),currentParameters);
                            String ret = (String)executePyroCall(pyroBridaService, "callexportfunction",new Object[] {dh.getFridaExportName(),currentParameters});
                            printSuccessMessage("* Ret value: " + ret);
                        } catch (Exception e) {
                            printException(e,"Error while running function " + dh.getName());
                        }
                    } else {
                        printException(null,"Error, start Pyro server and spawn application first.");
                    }
                }
            });
            lineJPanel.add(tempHookButton);
        }

        lineJPanel.add(tempHookLabel);

        if(dh.getOs() == BurpExtender.PLATFORM_ANDROID) {
            jPanelDefaultAndroidHooks.add(lineJPanel);
        } else {
            jPanelDefaultGenericHooks.add(lineJPanel);
        }

        return lineJPanel;

    }

    public void initializeDefaultHooks() {

        // Default Android hooks
        addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass with CA certificate, more reliable (requires CA public certificate in /data/local/tmp/cert-der.crt)",BurpExtender.PLATFORM_ANDROID,"androidpinningwithca1",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("SSL Pinning bypass without CA certificate, less reliable",BurpExtender.PLATFORM_ANDROID,"androidpinningwithoutca1",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Rooting check bypass",BurpExtender.PLATFORM_ANDROID,"androidrooting1",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Hook keystore stuff",BurpExtender.PLATFORM_ANDROID,"tracekeystore",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Hook crypto stuff",BurpExtender.PLATFORM_ANDROID,"dumpcryptostuff",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 1",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass1",true,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 2",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass2hook",true,new String[] {},null,false));

        // Default Android functions
        addButtonToHooksAndFunctions(new DefaultHook("Bypass fingerprint 2 (Enable the corresponding hook, trigger fingerprint screen and then run this function)",BurpExtender.PLATFORM_ANDROID,"androidfingerprintbypass2function",false,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Dump all aliases in keystore of predefined types",BurpExtender.PLATFORM_ANDROID,"listaliasesstatic",false,new String[] {},null,false));
        addButtonToHooksAndFunctions(new DefaultHook("Dump all aliases in keystore collected during runtime (through the \"Hook keystore stuff\" hook)",BurpExtender.PLATFORM_ANDROID,"listaliasesruntime",false,new String[] {},null,false));
    }
}
