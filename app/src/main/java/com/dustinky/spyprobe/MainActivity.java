package com.dustinky.spyprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.InputType;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.dustinky.spyprobe.BuildConfig;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * SpyProbe 控制台 UI
 *
 * Tab1 抓包：实时日志流（轮询 127.0.0.1:9901）+ 开关 + 导出
 * Tab2 探测：输入类名扫描方法 -> 点击方法即 hook
 * Tab3 说明
 *
 * 注意：server 在目标 App 进程内，目标 App 必须正在运行。
 */
public class MainActivity extends Activity {

    static final String PREFS = "spyprobe_ui";
    static final String KEY_TARGET = "target_pkg";
    static final String KEY_PORT = "port";

    SharedPreferences prefs;
    String targetPkg = "";
    int port = 9901;

    TextView statusView;
    TextView logView;
    Handler handler = new Handler(Looper.getMainLooper());
    long since = 0;
    boolean polling = false;

    // v1.2: 日志行缓存（过滤显示用）+ 过滤框
    EditText filterInput;
    List<String> allLogLines = new ArrayList<>();
    static final int MAX_LOG_LINES = 2000;
    // v1.8: 日志增量渲染指针 —— 记录 logView 已渲染到 allLogLines 的哪一行，
    // 无过滤时只 append 新行，避免每 800ms 全量 setText(2000 行) 卡 UI
    int renderedLines = 0;
    static final int MAX_DISPLAY = 1200; // logView 显示上限（超出重绘最近 N 行，防 TextView 无限膨胀）

    // 方法列表缓存（探测 Tab）
    List<String> methodSignatures = new ArrayList<>();
    List<String> methodParams = new ArrayList<>();
    Button btnTarget;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        targetPkg = prefs.getString(KEY_TARGET, "");
        port = prefs.getInt(KEY_PORT, 9901);

        buildUI();
    }

    @Override
    protected void onResume() {
        super.onResume();
        startPolling();
        refreshStatus();
    }

    @Override
    protected void onPause() {
        super.onPause();
        stopPolling();
    }

    // ================= UI 构建 =================
    private void buildUI() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(12), dp(12), dp(12), dp(12));
        root.setBackgroundColor(Color.parseColor("#111111"));

        // P0-1: Android 15 edge-to-edge insets 处理（顶部内容不被状态栏遮挡）
        root.setFitsSystemWindows(true);
        root.setOnApplyWindowInsetsListener((v, insets) -> {
            int top = insets.getInsets(WindowInsets.Type.systemBars()).top;
            int bottom = insets.getInsets(WindowInsets.Type.systemBars()).bottom;
            v.setPadding(dp(12), dp(12) + top, dp(12), dp(12) + bottom);
            return insets;
        });

        // 标题（v1.8: 版本号从 BuildConfig 动态取，杜绝硬编码不同步）
        TextView title = new TextView(this);
        title.setText("SpyProbe 逆向探测控制台 v" + BuildConfig.VERSION_NAME);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 20);
        title.setTextColor(Color.WHITE);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        // 目标选择 + 端口
        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        btnTarget = new Button(this);
        btnTarget.setText(targetPkg.isEmpty() ? "选择目标 App" : targetPkg);
        btnTarget.setOnClickListener(v -> pickTarget());
        row1.addView(btnTarget, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.6f));

        Button btnPort = new Button(this);
        btnPort.setText("端口:" + port);
        btnPort.setOnClickListener(v -> editPort());
        row1.addView(btnPort, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row1);

        // 状态
        statusView = new TextView(this);
        statusView.setText("未连接（目标 App 需在运行）");
        statusView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        statusView.setTextColor(Color.parseColor("#FFB74D"));
        statusView.setPadding(dp(4), dp(6), dp(4), dp(6));
        root.addView(statusView);

        // 开关行
        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        CheckBox cbSsl = new CheckBox(this);
        cbSsl.setText("SSL绕过");
        cbSsl.setChecked(true);
        cbSsl.setTextColor(Color.WHITE);
        cbSsl.setOnCheckedChangeListener((b, c) -> sendConfig("sslBypass", c));
        row2.addView(cbSsl);
        CheckBox cbOk = new CheckBox(this);
        cbOk.setText("OkHttp");
        cbOk.setChecked(true);
        cbOk.setTextColor(Color.WHITE);
        cbOk.setOnCheckedChangeListener((b, c) -> sendConfig("okhttp", c));
        row2.addView(cbOk);
        CheckBox cbUrl = new CheckBox(this);
        cbUrl.setText("URLConn");
        cbUrl.setChecked(true);
        cbUrl.setTextColor(Color.WHITE);
        cbUrl.setOnCheckedChangeListener((b, c) -> sendConfig("url", c));
        row2.addView(cbUrl);
        root.addView(row2);

        // v1.2: 第二开关行（DNS / TCP / 类加载）
        LinearLayout row2b = new LinearLayout(this);
        row2b.setOrientation(LinearLayout.HORIZONTAL);
        CheckBox cbDns = new CheckBox(this);
        cbDns.setText("DNS解析");
        cbDns.setChecked(true);
        cbDns.setTextColor(Color.WHITE);
        cbDns.setOnCheckedChangeListener((b, c) -> sendConfig("dns", c));
        row2b.addView(cbDns);
        CheckBox cbTcp = new CheckBox(this);
        cbTcp.setText("TCP连接");
        cbTcp.setChecked(true);
        cbTcp.setTextColor(Color.WHITE);
        cbTcp.setOnCheckedChangeListener((b, c) -> sendConfig("tcp", c));
        row2b.addView(cbTcp);
        CheckBox cbCls = new CheckBox(this);
        cbCls.setText("类加载");
        cbCls.setChecked(true);
        cbCls.setTextColor(Color.WHITE);
        cbCls.setOnCheckedChangeListener((b, c) -> sendConfig("classes", c));
        row2b.addView(cbCls);
        root.addView(row2b);

        // 按钮行：清空 / 导出 / 探测 / 已hook
        LinearLayout row3 = new LinearLayout(this);
        row3.setOrientation(LinearLayout.HORIZONTAL);
        Button btnClear = new Button(this);
        btnClear.setText("清空日志");
        btnClear.setOnClickListener(v -> sendClear());
        row3.addView(btnClear, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnExport = new Button(this);
        btnExport.setText("导出日志");
        btnExport.setOnClickListener(v -> exportLogs());
        row3.addView(btnExport, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnProbe = new Button(this);
        btnProbe.setText("函数探测");
        btnProbe.setOnClickListener(v -> showProbeDialog());
        row3.addView(btnProbe, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row3);

        // 第二行按钮：已hook列表 / 类加载 / 设置
        LinearLayout row4 = new LinearLayout(this);
        row4.setOrientation(LinearLayout.HORIZONTAL);
        Button btnHooks = new Button(this);
        btnHooks.setText("已Hook列表");
        btnHooks.setOnClickListener(v -> showHooksDialog());
        row4.addView(btnHooks, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnClasses = new Button(this);
        btnClasses.setText("类加载");
        btnClasses.setOnClickListener(v -> showClassesDialog());
        row4.addView(btnClasses, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnSettings = new Button(this);
        btnSettings.setText("设置");
        btnSettings.setOnClickListener(v -> showSettingsDialog());
        row4.addView(btnSettings, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        // v1.9: DexKit 按钮（导出 dex / 字符串反查）
        Button btnDex = new Button(this);
        btnDex.setText("DexKit");
        btnDex.setOnClickListener(v -> showDexKitDialog());
        row4.addView(btnDex, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(row4);

        // v1.2: 日志过滤行（关键字过滤显示 + 快捷 tag 筛选）
        LinearLayout rowFilter = new LinearLayout(this);
        rowFilter.setOrientation(LinearLayout.HORIZONTAL);
        filterInput = new EditText(this);
        filterInput.setHint("过滤关键字（如 /api/、Token）");
        filterInput.setTextColor(Color.WHITE);
        filterInput.setHintTextColor(Color.parseColor("#888888"));
        filterInput.setSingleLine(true);
        filterInput.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        rowFilter.addView(filterInput, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 2f));
        Button btnFilter = new Button(this);
        btnFilter.setText("过滤");
        btnFilter.setOnClickListener(v -> applyFilter());
        rowFilter.addView(btnFilter, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnFilterNet = new Button(this);
        btnFilterNet.setText("网络");
        btnFilterNet.setOnClickListener(v -> {
            filterInput.setText("(Net|DNS|TCP|HUC|OkHttp|SSL)");
            applyFilter();
        });
        rowFilter.addView(btnFilterNet, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnFilterMth = new Button(this);
        btnFilterMth.setText("函数");
        btnFilterMth.setOnClickListener(v -> {
            filterInput.setText("(Mth)");
            applyFilter();
        });
        rowFilter.addView(btnFilterMth, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        Button btnFilterAll = new Button(this);
        btnFilterAll.setText("全部");
        btnFilterAll.setOnClickListener(v -> {
            filterInput.setText("");
            applyFilter();
        });
        rowFilter.addView(btnFilterAll, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(rowFilter);

        // 日志滚动区
        ScrollView scroll = new ScrollView(this);
        logView = new TextView(this);
        logView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        logView.setTextColor(Color.parseColor("#A5D6A7"));
        logView.setTypeface(android.graphics.Typeface.MONOSPACE);
        logView.setText("");
        scroll.addView(logView);
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density + 0.5f);
    }

    // ================= 目标选择 =================
    /** v1.7: 读取已安装应用列表勾选（不再手输包名）—— 后台线程读，UI 列表展示 */
    private void pickTarget() {
        new Thread(() -> {
            final java.util.List<String[]> apps = new ArrayList<>(); // [label, pkg]
            try {
                PackageManager pm = getPackageManager();
                Intent launcher = new Intent(Intent.ACTION_MAIN);
                launcher.addCategory(Intent.CATEGORY_LAUNCHER);
                java.util.Set<String> seen = new java.util.HashSet<>();
                for (ResolveInfo ri : pm.queryIntentActivities(launcher, 0)) {
                    if (ri.activityInfo == null || ri.activityInfo.packageName == null) continue;
                    String pkgName = ri.activityInfo.packageName;
                    if (pkgName.equals(getPackageName())) continue; // 排除 SpyProbe 自己
                    if (!seen.add(pkgName)) continue;
                    String label;
                    try {
                        label = ri.loadLabel(pm).toString();
                    } catch (Throwable t) {
                        label = pkgName;
                    }
                    apps.add(new String[]{label, pkgName});
                }
                apps.sort((a, b) -> a[0].compareToIgnoreCase(b[0]));
            } catch (Throwable t) { }
            final java.util.List<String[]> fApps = apps;
            runOnUiThread(() -> showTargetPicker(fApps));
        }).start();
    }

    /** v1.7: 应用选择对话框（搜索框 + 列表勾选 + 手输兜底） */
    private void showTargetPicker(final java.util.List<String[]> apps) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(12), dp(8), dp(12), dp(8));

        EditText search = new EditText(this);
        search.setHint("搜索应用名 / 包名（如 微信 / com.tencent.mm）");
        box.addView(search);

        ListView list = new ListView(this);
        final java.util.List<String> display = new ArrayList<>();
        final java.util.List<String> pkgs = new ArrayList<>();
        for (String[] a : apps) {
            display.add(a[0] + "\n" + a[1]);
            pkgs.add(a[1]);
        }
        final ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_list_item_2, android.R.id.text1, display) {
            @Override
            public View getView(int position, View convertView, ViewGroup parent) {
                View v = super.getView(position, convertView, parent);
                try {
                    // 必须用 getItem(position)（过滤后正确项），不能用全量 display 索引
                    String item = String.valueOf(getItem(position));
                    String[] parts = item.split("\n");
                    TextView t1 = v.findViewById(android.R.id.text1);
                    TextView t2 = v.findViewById(android.R.id.text2);
                    t1.setText(parts[0]);
                    t1.setTextColor(Color.WHITE);
                    t1.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
                    t2.setText(parts.length > 1 ? parts[1] : "");
                    t2.setTextColor(Color.parseColor("#BBBBBB"));
                    t2.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
                } catch (Throwable t) { }
                return v;
            }
        };
        list.setAdapter(adapter);
        list.setBackgroundColor(Color.parseColor("#2A2A2A"));
        box.addView(list, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(380)));

        // 搜索过滤
        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int st, int c, int a) { }
            @Override public void onTextChanged(CharSequence s, int st, int b, int c) {
                String kw = s.toString().trim().toLowerCase();
                adapter.getFilter().filter(kw);
            }
            @Override public void afterTextChanged(Editable s) { }
        });

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("选择目标 App（" + apps.size() + " 个）")
                .setMessage("需先在 LSPosed 模块作用域中勾选该 App")
                .setView(box)
                .setNegativeButton("手输包名", (d, w) -> showManualPkgDialog())
                .setPositiveButton("取消", null)
                .create();

        list.setOnItemClickListener((parent, view, position, id) -> {
            // ArrayAdapter.getFilter 过滤后 position 对应过滤后列表，需从过滤后的数据取包名
            String selected;
            try {
                // 过滤后 count 变化，用 getItem 拿当前列表项
                selected = String.valueOf(adapter.getItem(position));
            } catch (Throwable t) {
                selected = null;
            }
            if (selected == null) return;
            String[] parts = selected.split("\n");
            String pkg = parts.length > 1 ? parts[1] : selected;
            applyTarget(pkg);
            dialog.dismiss();
        });
        dialog.show();
    }

    /** 手输包名兜底（列表搜不到时） */
    private void showManualPkgDialog() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT);
        input.setText(targetPkg);
        new AlertDialog.Builder(this)
                .setTitle("手输包名")
                .setMessage("请输入目标 App 包名（需先在 LSPosed 中为本模块勾选该包作用域）：")
                .setView(input)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, w) -> applyTarget(input.getText().toString().trim()))
                .show();
    }

    private void applyTarget(String pkg) {
        targetPkg = pkg;
        prefs.edit().putString(KEY_TARGET, targetPkg).apply();
        btnTarget.setText(targetPkg.isEmpty() ? "选择目标 App" : targetPkg);
        refreshStatus();
    }

    private void editPort() {
        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setText(String.valueOf(port));
        new AlertDialog.Builder(this)
                .setTitle("Server 端口（默认 9901）")
                .setView(input)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, w) -> {
                    try {
                        port = Integer.parseInt(input.getText().toString().trim());
                        prefs.edit().putInt(KEY_PORT, port).apply();
                        Toast.makeText(this, "端口已改，需重启目标 App 生效", Toast.LENGTH_SHORT).show();
                    } catch (Throwable t) { }
                })
                .show();
    }

    // ================= HTTP 调用 =================
    private String baseUrl() {
        return "http://127.0.0.1:" + port;
    }

    private String httpGet(String path) {
        try {
            URL u = new URL(baseUrl() + path);
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setConnectTimeout(1500);
            c.setReadTimeout(1500);
            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            r.close();
            c.disconnect();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private String httpPost(String path, String json) {
        try {
            URL u = new URL(baseUrl() + path);
            HttpURLConnection c = (HttpURLConnection) u.openConnection();
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "application/json");
            c.setConnectTimeout(1500);
            c.setReadTimeout(1500);
            c.setDoOutput(true);
            OutputStream os = c.getOutputStream();
            os.write(json.getBytes(StandardCharsets.UTF_8));
            os.flush();
            os.close();
            BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);
            r.close();
            c.disconnect();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    // ================= 轮询日志 =================
    private void startPolling() {
        if (polling) return;
        polling = true;
        handler.postDelayed(pollRunnable, 500);
    }

    private void stopPolling() {
        polling = false;
        handler.removeCallbacks(pollRunnable);
    }

    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            if (!polling) return;
            String resp = httpGet("/api/logs?since=" + since);
            if (resp != null) {
                try {
                    JSONObject o = new JSONObject(resp);
                    since = o.optLong("next", since);
                    JSONArray logs = o.optJSONArray("logs");
                    if (logs != null) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < logs.length(); i++) {
                            JSONObject e = logs.getJSONObject(i);
                            String line = e.optString("time") + " ["
                                    + e.optString("tag") + "] "
                                    + e.optString("msg");
                            // v1.2: 存缓存行（多行 msg 拆行存，过滤时按行匹配）
                            String[] lines = line.split("\n");
                            for (String ln : lines) {
                                allLogLines.add(ln);
                            }
                            sb.append(line).append('\n');
                        }
                        // 行数截断（防内存无限增长）
                        if (allLogLines.size() > MAX_LOG_LINES) {
                            int drop = allLogLines.size() - MAX_LOG_LINES;
                            allLogLines = new ArrayList<>(allLogLines.subList(drop, allLogLines.size()));
                            // v1.8: 截断后重置渲染指针并立即重绘，避免日志区短暂空白
                            logView.setText("");
                            renderedLines = 0;
                            appendFiltered();
                        }
                        if (sb.length() > 0) {
                            appendFiltered();
                            // 自动滚动到底部
                            final View sv = (View) logView.getParent();
                            sv.post(() -> sv.scrollTo(0, sv.getBottom() > 0 ? Integer.MAX_VALUE : 0));
                        }
                    }
                } catch (Throwable t) { }
            }
            handler.postDelayed(this, 800);
        }
    };

    /** v1.2: 按过滤关键字重绘日志区 */
    private void applyFilter() {
        // v1.8: 重置渲染指针（过滤变化需要全量重绘，增量指针已失效）
        logView.setText("");
        renderedLines = 0;
        appendFiltered();
    }

    private void appendFiltered() {
        String kw = filterInput.getText().toString().trim();
        if (kw.isEmpty()) {
            // v1.8: 无过滤 → 增量 append（只追加新行，避免全量 setText 卡顿）
            if (renderedLines > allLogLines.size()) {
                // 截断已重置指针的情况兜底
                logView.setText("");
                renderedLines = 0;
            }
            StringBuilder sb = new StringBuilder();
            for (int i = renderedLines; i < allLogLines.size(); i++) {
                sb.append(allLogLines.get(i)).append('\n');
            }
            if (sb.length() > 0) logView.append(sb.toString());
            renderedLines = allLogLines.size();
            // 显示超限：重绘最近 MAX_DISPLAY 行（防止 TextView 无限膨胀拖慢 UI）
            if (renderedLines > MAX_DISPLAY) {
                StringBuilder redraw = new StringBuilder();
                for (int i = allLogLines.size() - MAX_DISPLAY; i < allLogLines.size(); i++) {
                    redraw.append(allLogLines.get(i)).append('\n');
                }
                logView.setText(redraw.toString());
                renderedLines = allLogLines.size();
            }
            return;
        }
        // 有过滤：全量重绘（过滤场景行数少，无性能问题）
        StringBuilder sb = new StringBuilder();
        int n = Math.min(allLogLines.size(), MAX_LOG_LINES);
        for (int i = allLogLines.size() - n; i < allLogLines.size(); i++) {
            String line = allLogLines.get(i);
            if (matchesFilter(line, kw)) sb.append(line).append('\n');
        }
        logView.setText(sb.toString());
    }

    /** v1.8: 公共过滤匹配（正则优先，非法正则 fallback 字面匹配）—— 去重 exportLogs/appendFiltered 两处逻辑 */
    private boolean matchesFilter(String line, String kw) {
        if (kw == null || kw.isEmpty()) return true;
        java.util.regex.Pattern pat = null;
        try {
            pat = java.util.regex.Pattern.compile(kw, java.util.regex.Pattern.CASE_INSENSITIVE);
        } catch (Throwable t) { pat = null; }
        if (pat != null) return pat.matcher(line).find();
        return line.toLowerCase().contains(kw.toLowerCase());
    }

    private void refreshStatus() {
        // P1-8: HTTP 放后台线程，避免阻塞 UI
        new Thread(() -> {
            String resp = httpGet("/api/ping");
            if (resp == null) {
                // v1.3: 端口自动发现 —— 9901 连不上时扫描 9901-9910（多进程 app 可能偏移端口）
                int found = scanPorts();
                if (found > 0) {
                    port = found;
                    prefs.edit().putInt(KEY_PORT, port).apply();
                    resp = httpGet("/api/ping");
                }
            }
            final String fResp = resp;
            runOnUiThread(() -> {
                if (fResp != null) {
                    try {
                        JSONObject o = new JSONObject(fResp);
                        String p = o.optString("pkg", "?");
                        int count = o.optInt("logCount", 0);
                        int clsCount = o.optInt("classCount", 0);
                        // v1.2: 版本信息
                        StringBuilder st = new StringBuilder("● 已连接 ").append(p);
                        String vn = o.optString("versionName", "");
                        if (!vn.isEmpty()) st.append(" v").append(vn);
                        st.append("  (日志 ").append(count).append(" 条 / 类 ").append(clsCount).append(" 个)");
                        statusView.setText(st.toString());
                        statusView.setTextColor(Color.parseColor("#81C784"));
                    } catch (Throwable t) { }
                } else {
                    statusView.setText("○ 未连接：请先打开目标 App（" + baseUrl() + "）");
                    statusView.setTextColor(Color.parseColor("#FFB74D"));
                }
            });
        }).start();
    }

    /** v1.3: 扫描 9901-9910 找能 ping 通的 server 端口 */
    private int scanPorts() {
        for (int p = 9901; p <= 9910; p++) {
            if (p == port) continue; // 当前端口已试过
            try {
                URL u = new URL("http://127.0.0.1:" + p + "/api/ping");
                HttpURLConnection c = (HttpURLConnection) u.openConnection();
                c.setConnectTimeout(600);
                c.setReadTimeout(600);
                int code = c.getResponseCode();
                c.disconnect();
                if (code == 200) return p;
            } catch (Throwable t) { }
        }
        return -1;
    }

    // ================= 配置/清空 =================
    private void sendConfig(String key, boolean val) {
        new Thread(() -> {
            try {
                JSONObject o = new JSONObject();
                o.put(key, val);
                httpPost("/api/config", o.toString());
            } catch (Throwable t) { }
        }).start();
    }

    private void sendClear() {
        new Thread(() -> {
            String resp = httpPost("/api/clear", "{}");
            runOnUiThread(() -> {
                logView.setText("");
                allLogLines.clear();
                since = 0;
                renderedLines = 0; // v1.8: 清空后重置增量指针
                Toast.makeText(this, resp == null ? "未连接" : "已清空", Toast.LENGTH_SHORT).show();
            });
        }).start();
    }

    // ================= 导出 =================
    private void exportLogs() {
        new Thread(() -> {
            String resp = httpGet("/api/export");
            if (resp == null) {
                runOnUiThread(() -> Toast.makeText(this, "未连接，无法导出", Toast.LENGTH_SHORT).show());
                return;
            }
            try {
                JSONObject o = new JSONObject(resp);
                String text = o.optString("text", "");
                // v1.3: 如果设置了过滤关键字，导出过滤后的结果（抓包分析更聚焦）
                // v1.8: 复用公共 matchesFilter（去重两处过滤逻辑）
                String kw = filterInput.getText().toString().trim();
                if (!kw.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (String line : text.split("\n")) {
                        if (matchesFilter(line, kw)) sb.append(line).append('\n');
                    }
                    text = sb.toString();
                }
                final String fText = text;
                // SAF 导出
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("text/plain");
                intent.putExtra(Intent.EXTRA_TITLE, "SpyProbe_" + System.currentTimeMillis() + ".log");
                pendingExportText = fText;
                startActivityForResult(intent, 1001);
            } catch (Throwable t) {
                runOnUiThread(() -> Toast.makeText(this, "导出失败: " + t, Toast.LENGTH_SHORT).show());
            }
        }).start();
    }

    private String pendingExportText = null;

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 1001 && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            try {
                java.io.OutputStream os = getContentResolver().openOutputStream(uri);
                if (os != null) {
                    os.write(pendingExportText.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                    os.close();
                    Toast.makeText(this, "已导出 " + pendingExportText.length() + " 字符", Toast.LENGTH_SHORT).show();
                }
            } catch (Throwable t) {
                Toast.makeText(this, "写入失败: " + t, Toast.LENGTH_SHORT).show();
            }
        }
    }

    // ================= 函数探测 =================
    private void showProbeDialog() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));

        EditText input = new EditText(this);
        input.setHint("类名，如 com.example.app.Api");
        box.addView(input);

        TextView resultView = new TextView(this);
        resultView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        resultView.setTextColor(Color.BLACK);
        resultView.setPadding(dp(4), dp(8), dp(4), dp(4));
        box.addView(resultView);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(resultView);
        box.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(320)));

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("函数探测")
                .setView(box)
                .setPositiveButton("扫描", null)
                .setNegativeButton("关闭", null)
                .create();

        dialog.setOnShowListener(d -> {
            Button ok = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            ok.setOnClickListener(v -> {
                String cls = input.getText().toString().trim();
                if (cls.isEmpty()) {
                    Toast.makeText(this, "请输入类名", Toast.LENGTH_SHORT).show();
                    return;
                }
                scanAndShow(dialog, cls, resultView);
            });
        });
        dialog.show();
    }

    private void scanAndShow(AlertDialog dialog, String cls, TextView resultView) {
        resultView.setText("扫描中...");
        new Thread(() -> {
            try {
                JSONObject o = new JSONObject();
                o.put("class", cls);
                String resp = httpPost("/api/scan", o.toString());
                runOnUiThread(() -> {
                    if (resp == null) {
                        resultView.setText("未连接");
                        return;
                    }
                    try {
                        JSONObject r = new JSONObject(resp);
                        if (!r.optBoolean("ok", false)) {
                            resultView.setText(r.optString("error", "error"));
                            return;
                        }
                        JSONArray methods = r.optJSONArray("methods");
                        methodSignatures.clear();
                        methodParams.clear();
                        StringBuilder sb = new StringBuilder();
                        sb.append("类 ").append(r.optString("className")).append(" 共 ")
                          .append(methods == null ? 0 : methods.length()).append(" 个成员\n");
                        sb.append("（点击下方“选择方法”可 hook；字段为只读探测）\n\n");
                        if (methods != null) {
                            for (int i = 0; i < methods.length(); i++) {
                                JSONObject m = methods.getJSONObject(i);
                                String sig = m.optString("signature", "?");
                                String params = m.optString("params", "");
                                String kind = m.optString("kind", "method");
                                String mods = m.optString("modifiers", "");
                                methodSignatures.add(sig);
                                methodParams.add(params);
                                sb.append(i).append(") [").append(kind).append("] ").append(mods).append(" ")
                                  .append(sig).append('\n');
                            }
                        }
                        resultView.setText(sb.toString());
                        // P1-2: 点击结果弹"选择方法"列表，点具体方法名即 hook
                        final String fcls = cls;
                        resultView.setOnClickListener(v -> showMethodPicker(fcls));
                        resultView.setOnLongClickListener(v -> {
                            showMethodPicker(fcls);
                            return true;
                        });
                    } catch (Throwable t) {
                        resultView.setText("解析失败: " + t);
                    }
                });
            } catch (Throwable t) {
                runOnUiThread(() -> resultView.setText("请求失败: " + t));
            }
        }).start();
    }

    /** P1-2: 方法选择列表 -> 点具体方法即 hook */
    private void showMethodPicker(final String cls) {
        if (methodSignatures.isEmpty()) {
            Toast.makeText(this, "请先扫描类", Toast.LENGTH_SHORT).show();
            return;
        }
        String[] items = methodSignatures.toArray(new String[0]);
        new AlertDialog.Builder(this)
                .setTitle("选择方法 hook - " + cls)
                .setItems(items, (d, which) -> {
                    String params = which < methodParams.size() ? methodParams.get(which) : "";
                    sendHook(cls, methodSignatures.get(which), params);
                })
                .setNegativeButton("取消", null)
                .show();
    }

    /** 发送 hook 请求（method 为 signature 如 "foo(java.lang.String,int)"，解析出方法名+参数） */
    private void sendHook(final String cls, String signature, String fallbackParams) {
        String method = signature;
        String params = fallbackParams;
        if (method.contains("(")) {
            int pi = method.indexOf('(');
            int end = method.lastIndexOf(')');
            String inner = end > pi ? method.substring(pi + 1, end).trim() : "";
            method = method.substring(0, pi).trim();
            if (!inner.isEmpty()) {
                // 参数可能是 "java.lang.String, int"，去掉空格
                String[] parts = inner.split(",");
                StringBuilder sb = new StringBuilder();
                for (String p : parts) {
                    if (sb.length() > 0) sb.append(",");
                    sb.append(p.trim());
                }
                params = sb.toString();
            } else {
                params = "";
            }
        }
        final String fMethod = method;
        final String fParams = params;
        new Thread(() -> {
            try {
                JSONObject o = new JSONObject();
                o.put("class", cls);
                o.put("method", fMethod);
                o.put("params", fParams);
                String resp = httpPost("/api/hook", o.toString());
                runOnUiThread(() -> {
                    if (resp == null) {
                        Toast.makeText(this, "未连接", Toast.LENGTH_SHORT).show();
                    } else {
                        try {
                            JSONObject r = new JSONObject(resp);
                            String note = r.optString("note", resp);
                            int hooked = r.optInt("hooked", 0);
                            Toast.makeText(this, "hook " + hooked + " 个: " + note, Toast.LENGTH_LONG).show();
                        } catch (Throwable t) {
                            Toast.makeText(this, resp, Toast.LENGTH_LONG).show();
                        }
                    }
                });
            } catch (Throwable t) {
                runOnUiThread(() -> Toast.makeText(this, "hook 失败: " + t, Toast.LENGTH_SHORT).show());
            }
        }).start();
    }

    /** v1.2: 类加载记录查看（关键字过滤 + 刷屏开关） */
    private void showClassesDialog() {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));

        EditText input = new EditText(this);
        input.setHint("类名关键字，如 api / network / utils");
        box.addView(input);

        CheckBox cbLogAll = new CheckBox(this);
        cbLogAll.setText("匹配的类刷屏到日志");
        cbLogAll.setTextColor(Color.BLACK);
        box.addView(cbLogAll);

        TextView resultView = new TextView(this);
        resultView.setTextSize(TypedValue.COMPLEX_UNIT_SP, 11);
        resultView.setTextColor(Color.BLACK);
        resultView.setTypeface(android.graphics.Typeface.MONOSPACE);
        resultView.setPadding(dp(4), dp(8), dp(4), dp(4));
        box.addView(resultView);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(resultView);
        box.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(360)));

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("类加载记录（ClassLoader.loadClass）")
                .setMessage("显示目标 App 已加载的类名，可关键字过滤定位核心类")
                .setView(box)
                .setPositiveButton("查询", null)
                .setNegativeButton("关闭", null)
                .create();

        dialog.setOnShowListener(d -> {
            Button ok = dialog.getButton(AlertDialog.BUTTON_POSITIVE);
            ok.setOnClickListener(v -> {
                String kw = input.getText().toString().trim();
                boolean logAll = cbLogAll.isChecked();
                resultView.setText("查询中...");
                new Thread(() -> {
                    try {
                        String path = "/api/classes?filter=" + Uri.encode(kw) + (logAll ? "&logall=true" : "");
                        String resp = httpGet(path);
                        runOnUiThread(() -> {
                            if (resp == null) {
                                resultView.setText("未连接");
                                return;
                            }
                            try {
                                JSONObject r = new JSONObject(resp);
                                int count = r.optInt("count", 0);
                                int total = r.optInt("total", 0);
                                // v1.3: classes 改为 JSONArray 返回
                                JSONArray clsArr = r.optJSONArray("classes");
                                StringBuilder sb = new StringBuilder();
                                sb.append("共 ").append(total).append(" 个类，匹配 ").append(count).append(" 个：\n\n");
                                if (clsArr != null) {
                                    int n = Math.min(clsArr.length(), 2000);
                                    for (int i = 0; i < n; i++) {
                                        sb.append(clsArr.getString(i)).append('\n');
                                    }
                                    if (clsArr.length() > n) sb.append("... 仅显示前 ").append(n).append(" 个\n");
                                }
                                resultView.setText(sb.toString());
                            } catch (Throwable t) {
                                resultView.setText("解析失败: " + t);
                            }
                        });
                    } catch (Throwable t) {
                        runOnUiThread(() -> resultView.setText("请求失败: " + t));
                    }
                }).start();
            });
        });
        dialog.show();
    }

    /** 已 hook 列表对话框（P1-6/7） */
    private void showHooksDialog() {
        new Thread(() -> {
            String resp = httpGet("/api/hooks");
            runOnUiThread(() -> {
                if (resp == null) {
                    Toast.makeText(this, "未连接", Toast.LENGTH_SHORT).show();
                    return;
                }
                try {
                    JSONObject o = new JSONObject(resp);
                    JSONArray hooks = o.optJSONArray("hooks");
                    if (hooks == null || hooks.length() == 0) {
                        new AlertDialog.Builder(this)
                                .setTitle("已 Hook 列表")
                                .setMessage("当前没有活跃 hook")
                                .setPositiveButton("OK", null)
                                .show();
                        return;
                    }
                    String[] items = new String[hooks.length()];
                    final String[] classes = new String[hooks.length()];
                    final String[] methods = new String[hooks.length()];
                    final String[] paramss = new String[hooks.length()];
                    for (int i = 0; i < hooks.length(); i++) {
                        JSONObject h = hooks.getJSONObject(i);
                        String c = h.optString("class", "?");
                        String m = h.optString("method", "?");
                        String p = h.optString("params", "");
                        classes[i] = c;
                        methods[i] = m;
                        paramss[i] = p;
                        items[i] = c + "." + m + "(" + p + ")";
                    }
                    new AlertDialog.Builder(this)
                            .setTitle("已 Hook 列表（点击单项操作）")
                            .setItems(items, (d, which) -> {
                                // v1.4: 单项操作菜单（卸载 / 设置劫持 / 取消劫持 / 查看劫持）
                                new AlertDialog.Builder(this)
                                        .setTitle("操作 - " + items[which])
                                        .setItems(new String[]{"卸载 hook", "设置劫持返回值", "取消劫持", "查看当前劫持"},
                                                (d2, w2) -> {
                                                    switch (w2) {
                                                        case 0:
                                                            sendUnhook(classes[which], methods[which], paramss[which]);
                                                            break;
                                                        case 1:
                                                            showHijackDialog(classes[which], methods[which], paramss[which]);
                                                            break;
                                                        case 2:
                                                            sendHijack(classes[which], methods[which], paramss[which], null);
                                                            break;
                                                        case 3:
                                                            showHijacksDialog();
                                                            break;
                                                    }
                                                })
                                        .setNegativeButton("取消", null)
                                        .show();
                            })
                            .setNegativeButton("取消", null)
                            .setPositiveButton("全部卸载", (d, w) -> {
                                for (int i = 0; i < classes.length; i++) {
                                    sendUnhook(classes[i], methods[i], paramss[i]);
                                }
                            })
                            .show();
                } catch (Throwable t) {
                    Toast.makeText(this, "解析失败: " + t, Toast.LENGTH_SHORT).show();
                }
            });
        }).start();
    }

    private void sendUnhook(final String cls, final String method, final String params) {
        new Thread(() -> {
            try {
                JSONObject o = new JSONObject();
                o.put("class", cls);
                o.put("method", method);
                o.put("params", params);
                httpPost("/api/unhook", o.toString());
            } catch (Throwable t) { }
        }).start();
    }

    // ================= v1.4: 返回值劫持 =================

    /** 设置劫持对话框：输入强制返回值（true/false、数字、文本、null=返回空） */
    private void showHijackDialog(final String cls, final String method, final String params) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));

        TextView tip = new TextView(this);
        tip.setText("输入强制返回值（命中后不执行原方法，直接返回）：\n" +
                "• true / false —— boolean 方法\n" +
                "• 123 / 3.14 —— 数字方法\n" +
                "• 任意文本 —— String 方法\n" +
                "• null —— 返回空（对象方法）\n" +
                "• 留空 = 返回空串");
        tip.setTextSize(TypedValue.COMPLEX_UNIT_SP, 12);
        tip.setTextColor(Color.BLACK);
        box.addView(tip);

        EditText input = new EditText(this);
        input.setHint("如 true");
        box.addView(input);

        new AlertDialog.Builder(this)
                .setTitle("劫持 " + method)
                .setMessage("class: " + cls + "\nparams: " + (params.isEmpty() ? "全部重载" : params))
                .setView(box)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定劫持", (d, w) -> {
                    String val = input.getText().toString().trim();
                    if (val.isEmpty()) val = "";
                    sendHijack(cls, method, params, val);
                    Toast.makeText(this, "劫持已设置: " + method + " -> " + val, Toast.LENGTH_LONG).show();
                })
                .show();
    }

    /** 发送劫持/取消劫持；value 为 null 表示取消 */
    private void sendHijack(final String cls, final String method, final String params, final String value) {
        new Thread(() -> {
            try {
                JSONObject o = new JSONObject();
                o.put("class", cls);
                o.put("method", method);
                o.put("params", params);
                if (value == null) {
                    o.put("value", JSONObject.NULL); // JSON null → 服务端取消劫持
                } else {
                    o.put("value", value);
                }
                httpPost("/api/hijack", o.toString());
            } catch (Throwable t) { }
        }).start();
    }

    /** 查看当前劫持规则列表 */
    private void showHijacksDialog() {
        new Thread(() -> {
            String resp = httpGet("/api/hijacks");
            runOnUiThread(() -> {
                if (resp == null) {
                    Toast.makeText(this, "未连接", Toast.LENGTH_SHORT).show();
                    return;
                }
                try {
                    JSONObject o = new JSONObject(resp);
                    JSONArray arr = o.optJSONArray("hijacks");
                    if (arr == null || arr.length() == 0) {
                        new AlertDialog.Builder(this)
                                .setTitle("当前劫持规则")
                                .setMessage("没有劫持规则")
                                .setPositiveButton("OK", null)
                                .show();
                        return;
                    }
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < arr.length(); i++) {
                        JSONObject h = arr.getJSONObject(i);
                        sb.append(h.optString("class")).append(".").append(h.optString("method"))
                          .append("(").append(h.optString("params")).append(")")
                          .append(" -> ").append(h.optString("value")).append('\n');
                    }
                    new AlertDialog.Builder(this)
                            .setTitle("当前劫持规则")
                            .setMessage(sb.toString())
                            .setPositiveButton("OK", null)
                            .show();
                } catch (Throwable t) {
                    Toast.makeText(this, "解析失败: " + t, Toast.LENGTH_SHORT).show();
                }
            });
        }).start();
    }

    /** 设置对话框（v1.5: ScrollView 包裹防溢出 + 全部探测开关） */
    private void showSettingsDialog() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));

        TextView tip = new TextView(this);
        tip.setText("响应体记录上限(字节)，0=不记录body");
        tip.setTextColor(Color.BLACK);
        box.addView(tip);

        EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER);
        input.setHint("默认 2048");
        box.addView(input);

        CheckBox cbWeb = new CheckBox(this);
        cbWeb.setText("记录 WebView.loadUrl");
        cbWeb.setTextColor(Color.BLACK);
        cbWeb.setChecked(true);
        box.addView(cbWeb);

        CheckBox cbPrefs = new CheckBox(this);
        cbPrefs.setText("记录 SharedPreferences key（读取高频，建议按需开）");
        cbPrefs.setTextColor(Color.BLACK);
        cbPrefs.setChecked(false);
        box.addView(cbPrefs);

        CheckBox cbSql = new CheckBox(this);
        cbSql.setText("记录 SQLite 增删改查");
        cbSql.setTextColor(Color.BLACK);
        cbSql.setChecked(true);
        box.addView(cbSql);

        // v1.5: 反编译增强探测开关
        CheckBox cbUrlBuild = new CheckBox(this);
        cbUrlBuild.setText("记录 URL 构造（找接口地址/CDN 域名）");
        cbUrlBuild.setTextColor(Color.BLACK);
        cbUrlBuild.setChecked(true);
        box.addView(cbUrlBuild);

        CheckBox cbLogcat = new CheckBox(this);
        cbLogcat.setText("拦截 App 自身 Log 输出（信息量大）");
        cbLogcat.setTextColor(Color.BLACK);
        cbLogcat.setChecked(true);
        box.addView(cbLogcat);

        CheckBox cbCrypto = new CheckBox(this);
        cbCrypto.setText("记录加密算法/密钥/IV（Cipher，默认关防刷屏）");
        cbCrypto.setTextColor(Color.BLACK);
        cbCrypto.setChecked(false);
        box.addView(cbCrypto);

        CheckBox cbAct = new CheckBox(this);
        cbAct.setText("记录 Activity 生命周期 + Intent 跳转");
        cbAct.setTextColor(Color.BLACK);
        cbAct.setChecked(false);
        box.addView(cbAct);

        CheckBox cbJson = new CheckBox(this);
        cbJson.setText("记录 JSON/Gson 序列化结构");
        cbJson.setTextColor(Color.BLACK);
        cbJson.setChecked(false);
        box.addView(cbJson);

        // v1.6: 函数探测详细模式开关（关=轻量只记参数摘要，hook 高频方法不拖慢 app）
        CheckBox cbDetail = new CheckBox(this);
        cbDetail.setText("函数探测详细模式（参数/字段/调用栈）");
        cbDetail.setTextColor(Color.BLACK);
        cbDetail.setChecked(true);
        box.addView(cbDetail);

        // v1.9: 环境检测 / TLS / 连接点 / Cronet 开关
        CheckBox cbEnv = new CheckBox(this);
        cbEnv.setText("记录环境检测（root/vpn/传感器/防截屏/设备指纹）");
        cbEnv.setTextColor(Color.BLACK);
        cbEnv.setChecked(true);
        box.addView(cbEnv);

        CheckBox cbTls = new CheckBox(this);
        cbTls.setText("TLS 明文抓包（ConscryptEngine，HTTPS 明文头）");
        cbTls.setTextColor(Color.BLACK);
        cbTls.setChecked(true);
        box.addView(cbTls);

        CheckBox cbConnect = new CheckBox(this);
        cbConnect.setText("万能连接点记录（BlockGuardOs.connect，QUIC/自建TCP）");
        cbConnect.setTextColor(Color.BLACK);
        cbConnect.setChecked(true);
        box.addView(cbConnect);

        CheckBox cbCronet = new CheckBox(this);
        cbCronet.setText("Cronet 网络栈记录（字节系 app，默认关防重复）");
        cbCronet.setTextColor(Color.BLACK);
        cbCronet.setChecked(false);
        box.addView(cbCronet);

        scroll.addView(box);

        new AlertDialog.Builder(this)
                .setTitle("设置")
                .setView(scroll)
                .setNegativeButton("取消", null)
                .setPositiveButton("确定", (d, w) -> {
                    // v1.7: 上限输入非法时用默认 2048，其余配置照常下发（原实现 parseInt 失败直接跳 catch，谎报"其余已下发"）
                    int limit = 2048;
                    try {
                        String s = input.getText().toString().trim();
                        if (!s.isEmpty()) limit = Integer.parseInt(s);
                    } catch (Throwable t) { }
                    final int fLimit = limit;
                    new Thread(() -> {
                        try {
                            JSONObject o = new JSONObject();
                            o.put("bodyLimit", fLimit);
                            o.put("webView", cbWeb.isChecked());
                            o.put("prefs", cbPrefs.isChecked());
                            o.put("sqlite", cbSql.isChecked());
                            o.put("urlBuild", cbUrlBuild.isChecked());
                            o.put("logcat", cbLogcat.isChecked());
                            o.put("crypto", cbCrypto.isChecked());
                            o.put("activity", cbAct.isChecked());
                            o.put("json", cbJson.isChecked());
                            o.put("detailMode", cbDetail.isChecked()); // v1.6
                            o.put("env", cbEnv.isChecked());          // v1.9
                            o.put("tls", cbTls.isChecked());
                            o.put("connect", cbConnect.isChecked());
                            o.put("cronet", cbCronet.isChecked());
                            httpPost("/api/config", o.toString());
                        } catch (Throwable t) { }
                    }).start();
                    Toast.makeText(this, "配置已下发", Toast.LENGTH_SHORT).show();
                })
                .show();
    }

    /** v1.9: DexKit 功能对话框（导出 dex / 字符串反查 / 释放） */
    private void showDexKitDialog() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));

        TextView tip = new TextView(this);
        tip.setText("DexKit：导出全部 dex（jadx 打开）+ 字符串反查方法（找校验/密钥/接口逻辑）");
        tip.setTextColor(Color.BLACK);
        box.addView(tip);

        Button btnDump = new Button(this);
        btnDump.setText("导出 dex 到 Download/SpyProbeDump/");
        btnDump.setOnClickListener(v -> {
            Toast.makeText(this, "导出中…", Toast.LENGTH_SHORT).show();
            new Thread(() -> {
                try {
                    String r = httpGet("/api/dexdump");
                    runOnUiThread(() -> Toast.makeText(this, "导出结果: " + r, Toast.LENGTH_LONG).show());
                } catch (Throwable t) {
                    runOnUiThread(() -> Toast.makeText(this, "导出失败: " + t, Toast.LENGTH_SHORT).show());
                }
            }).start();
        });
        box.addView(btnDump);

        EditText input = new EditText(this);
        input.setHint("输入字符串，反查引用它的方法");
        box.addView(input);

        Button btnFind = new Button(this);
        btnFind.setText("字符串反查");
        btnFind.setOnClickListener(v -> {
            String s = input.getText().toString().trim();
            if (s.isEmpty()) {
                Toast.makeText(this, "请输入字符串", Toast.LENGTH_SHORT).show();
                return;
            }
            Toast.makeText(this, "反查中…", Toast.LENGTH_SHORT).show();
            new Thread(() -> {
                try {
                    JSONObject body = new JSONObject();
                    body.put("str", s);
                    String r = httpPost("/api/stringfind", body.toString());
                    runOnUiThread(() -> showStringFindResult(s, r));
                } catch (Throwable t) {
                    runOnUiThread(() -> Toast.makeText(this, "反查失败: " + t, Toast.LENGTH_SHORT).show());
                }
            }).start();
        });
        box.addView(btnFind);

        Button btnClose = new Button(this);
        btnClose.setText("释放 DexKit（省内存）");
        btnClose.setOnClickListener(v -> {
            new Thread(() -> {
                try { httpGet("/api/dexclose"); } catch (Throwable t) { }
            }).start();
            Toast.makeText(this, "已释放", Toast.LENGTH_SHORT).show();
        });
        box.addView(btnClose);

        scroll.addView(box);
        new AlertDialog.Builder(this)
                .setTitle("DexKit 反编译")
                .setView(scroll)
                .setPositiveButton("关闭", null)
                .show();
    }

    /** v1.9: 字符串反查结果展示（列表 + 一键复制） */
    private void showStringFindResult(String query, String json) {
        try {
            JSONObject o = new JSONObject(json);
            if (!o.optBoolean("ok", false)) {
                Toast.makeText(this, "反查失败: " + o.optString("error"), Toast.LENGTH_SHORT).show();
                return;
            }
            int total = o.optInt("total", 0);
            int shown = o.optInt("shown", 0);
            JSONArray arr = o.optJSONArray("methods");
            StringBuilder sb = new StringBuilder();
            sb.append("共 ").append(total).append(" 个方法引用 \"").append(query).append("\"\n\n");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject m = arr.getJSONObject(i);
                    sb.append(m.optString("class")).append(".").append(m.optString("method"))
                      .append("(").append(m.optString("params")).append(")\n");
                }
            }
            if (shown < total) sb.append("\n…仅显示前 ").append(shown).append(" 个");
            final String text = sb.toString();
            new AlertDialog.Builder(this)
                    .setTitle("字符串反查结果")
                    .setMessage(text)
                    .setPositiveButton("复制", (d, w) -> {
                        android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("spyprobe", text));
                        Toast.makeText(this, "已复制", Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton("关闭", null)
                    .show();
        } catch (Throwable t) {
            Toast.makeText(this, "解析失败: " + t, Toast.LENGTH_SHORT).show();
        }
    }
}
