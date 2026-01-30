#!/bin/bash

# --- 配置 ---
PANEL_PORT="4794"
DEFAULT_USER="admin"
DEFAULT_PASS="123456"

# --- 路径 ---
REALM_BIN="/usr/local/bin/realm"
REALM_CONFIG="/etc/realm/config.toml"
WORK_DIR="/opt/realm_panel"
BINARY_PATH="/usr/local/bin/realm-panel"
DATA_FILE="/etc/realm/panel_data.json"

# --- 颜色与动画 ---
GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
CYAN="\033[36m"
RESET="\033[0m"

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -n " "
    while [ -d /proc/$pid ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_step() {
    echo -e -n "${CYAN}>>> $1...${RESET}"
    eval "$2" >/dev/null 2>&1 &
    spinner $!
    echo -e "${GREEN} [完成]${RESET}"
}

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请以 root 用户运行！${RESET}"
    exit 1
fi

clear
echo -e "${GREEN}==========================================${RESET}"
echo -e "${GREEN}Realm 面板 (流量统计+配额+到期) 修复版${RESET}"
echo -e "${GREEN}==========================================${RESET}"

# 1. 系统优化 (解决断流关键)
echo -e -n "${CYAN}>>> 优化系统文件描述符限制...${RESET}"
cat > /etc/security/limits.d/realm.conf <<EOF
root soft nofile 1048576
root hard nofile 1048576
* soft nofile 1048576
* hard nofile 1048576
EOF
ulimit -n 1048576
echo -e "${GREEN} [完成]${RESET}"

# 2. 环境准备
OS_ARCH=$(uname -m)
if [ -f /etc/debian_version ]; then
    run_step "更新系统软件源" "apt-get update -y"
    if [[ "$OS_ARCH" == "x86_64" ]]; then
        run_step "安装系统基础依赖" "apt-get install -y curl wget tar build-essential pkg-config libssl-dev gcc-multilib iptables"
    else
        run_step "安装系统基础依赖" "apt-get install -y curl wget tar build-essential pkg-config libssl-dev iptables"
    fi
elif [ -f /etc/redhat-release ]; then
    run_step "安装开发工具包" "yum groupinstall -y 'Development Tools'"
    run_step "安装基础依赖" "yum install -y curl wget tar openssl-devel libgcc glibc-static iptables"
fi

if ! command -v cargo &> /dev/null; then
    echo -e -n "${CYAN}>>> 安装 Rust 编译器...${RESET}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1 &
    spinner $!
    echo -e "${GREEN} [完成]${RESET}"
    source "$HOME/.cargo/env"
fi

# 3. Realm 主程序
if [ ! -f "$REALM_BIN" ]; then
    echo -e -n "${CYAN}>>> 下载并安装 Realm 主程序...${RESET}"
    if [[ "$OS_ARCH" == "x86_64" ]]; then
        URL="https://github.com/zhboner/realm/releases/latest/download/realm-x86_64-unknown-linux-gnu.tar.gz"
    elif [[ "$OS_ARCH" == "aarch64" ]]; then
        URL="https://github.com/zhboner/realm/releases/latest/download/realm-aarch64-unknown-linux-gnu.tar.gz"
    else
        echo -e "${RED}不支持架构: $OS_ARCH${RESET}"
        exit 1
    fi
    mkdir -p /tmp/realm_tmp
    (
        wget -O /tmp/realm_tmp/realm.tar.gz "$URL" -q
        tar -xvf /tmp/realm_tmp/realm.tar.gz -C /tmp/realm_tmp >/dev/null 2>&1
        mv /tmp/realm_tmp/realm "$REALM_BIN"
        chmod +x "$REALM_BIN"
    ) >/dev/null 2>&1 &
    spinner $!
    rm -rf /tmp/realm_tmp
    echo -e "${GREEN} [完成]${RESET}"
fi
mkdir -p "$(dirname "$REALM_CONFIG")"

# 4. 生成代码
run_step "生成 Rust 源代码" "
rm -rf '$WORK_DIR'
mkdir -p '$WORK_DIR/src'
"
cd "$WORK_DIR" || exit 1

cat > Cargo.toml <<EOF
[package]
name = "realm-panel"
version = "5.0.0"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
tower-cookies = "0.10"
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde", "clock"] }
EOF

cat > src/main.rs << 'EOF'
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
    Form, Json, Router,
};
use chrono::{DateTime, Local, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::Path as FilePath,
    process::Command,
    sync::{Arc, Mutex},
};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use uuid::Uuid;

const REALM_CONFIG: &str = "/etc/realm/config.toml";
const DATA_FILE: &str = "/etc/realm/panel_data.json";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Rule {
    id: String,
    name: String,
    listen: String,
    remote: String,
    enabled: bool,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    quota_bytes: Option<u64>,
}

// 用于前端显示的扩展结构
#[derive(Serialize, Clone, Debug)]
struct RuleWithStats {
    #[serde(flatten)]
    rule: Rule,
    used_bytes: u64, // 实时流量
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AdminConfig {
    username: String,
    pass_hash: String,
    #[serde(default = "default_bg_pc")]
    bg_pc: String,
    #[serde(default = "default_bg_mobile")]
    bg_mobile: String,
}
fn default_bg_pc() -> String { "https://img.inim.im/file/1769439286929_61891168f564c650f6fb03d1962e5f37.jpeg".to_string() }
fn default_bg_mobile() -> String { "https://img.inim.im/file/1764296937373_bg_m_2.png".to_string() }

#[derive(Serialize, Deserialize, Clone, Debug)]
struct AppData {
    admin: AdminConfig,
    rules: Vec<Rule>,
}

#[derive(Serialize)]
struct RealmEndpoint {
    name: String,
    listen: String,
    remote: String,
    #[serde(rename = "type")]
    r#type: String,
}
#[derive(Serialize)]
struct RealmConfig {
    endpoints: Vec<RealmEndpoint>,
}

struct AppState {
    data: Mutex<AppData>,
}

#[tokio::main]
async fn main() {
    let initial_data = load_or_init_data();
    let state = Arc::new(AppState {
        data: Mutex::new(initial_data),
    });

    // 初始化：清理并重新应用所有流量规则，确保 iptables 准确
    {
        let data = state.data.lock().unwrap();
        let _ = run_iptables(vec!["-F", "INPUT"]); // 清空 INPUT 链，防止重复
        // 重新对每个启用规则添加统计
        for rule in &data.rules {
             if rule.enabled {
                 if let Some(port) = extract_listen_port(&rule.listen) {
                     let _ = iptables_ensure_rule(port, rule.quota_bytes);
                 }
             }
        }
    }

    // 后台任务：监控过期和超额
    let state_cloned = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            check_status(&state_cloned);
        }
    });

    let app = Router::new()
        .route("/", get(index_page))
        .route("/login", get(login_page).post(login_action))
        .route("/api/rules", get(get_rules).post(add_rule))
        .route("/api/rules/batch", post(batch_add_rules))
        .route("/api/rules/all", delete(delete_all_rules))
        .route("/api/rules/:id", put(update_rule).delete(delete_rule))
        .route("/api/rules/:id/toggle", post(toggle_rule))
        .route("/api/rules/:id/reset_traffic", post(reset_traffic))
        .route("/api/admin/account", post(update_account))
        .route("/api/admin/bg", post(update_bg))
        .route("/api/backup", get(download_backup))
        .route("/api/restore", post(restore_backup))
        .route("/logout", post(logout_action))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let port = std::env::var("PANEL_PORT").unwrap_or_else(|_| "4794".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn check_status(state: &Arc<AppState>) {
    let mut data = state.data.lock().unwrap();
    let now = Utc::now().timestamp();
    let mut changed = false;
    let traffic_map = fetch_traffic_map();

    for r in data.rules.iter_mut() {
        if !r.enabled { continue; }
        
        // 1. 检查过期
        if let Some(exp) = r.expires_at {
            if exp <= now {
                r.enabled = false;
                changed = true;
                // 移除 iptables 规则
                if let Some(port) = extract_listen_port(&r.listen) {
                    let _ = iptables_del_rule(port);
                }
                continue;
            }
        }

        // 2. 检查配额
        if let Some(quota) = r.quota_bytes {
            if let Some(port) = extract_listen_port(&r.listen) {
                let used = *traffic_map.get(&port).unwrap_or(&0);
                // 注意：这里我们用 iptables 的计数器作为已用流量
                // 如果已用流量 > 配额，则禁用规则（或者让 iptables 自身去 REJECT）
                // 脚本为了简单，这里选择“软限制”，即面板检测到超额后自动停用 Realm 转发
                if used >= quota {
                    r.enabled = false; // 停用
                    changed = true;
                    let _ = iptables_del_rule(port);
                }
            }
        }
    }

    if changed {
        save_json(&data);
        save_config_toml(&data);
    }
}

// 读取 iptables -nxvL INPUT 的输出，解析每个端口的字节数
fn fetch_traffic_map() -> HashMap<u16, u64> {
    let mut map = HashMap::new();
    if let Ok(output) = Command::new("iptables").args(["-n", "-x", "-v", "-L", "INPUT"]).output() {
        let out_str = String::from_utf8_lossy(&output.stdout);
        for line in out_str.lines() {
            // 典型输出: 
            // 1234  2048576 ACCEPT  tcp  --  * * 0.0.0.0/0  0.0.0.0/0  tcp dpt:10000
            // 列通常是: pkts bytes target prot opt in out source destination options
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 9 { continue; }
            
            // 尝试找 bytes (第2列) 和 dpt:端口
            if let Ok(bytes) = parts[1].parse::<u64>() {
                // 找端口
                for part in &parts {
                    if part.starts_with("dpt:") {
                        if let Ok(port) = part[4..].parse::<u16>() {
                            map.insert(port, bytes);
                        }
                    }
                }
            }
        }
    }
    map
}

fn load_or_init_data() -> AppData {
    if let Ok(content) = fs::read_to_string(DATA_FILE) {
        if let Ok(mut data) = serde_json::from_str::<AppData>(&content) {
            data.rules.retain(|r| r.name != "system-keepalive");
            save_config_toml(&data);
            return data;
        }
    }
    let admin = AdminConfig {
        username: std::env::var("PANEL_USER").unwrap_or("admin".to_string()),
        pass_hash: std::env::var("PANEL_PASS").unwrap_or("123456".to_string()),
        bg_pc: default_bg_pc(),
        bg_mobile: default_bg_mobile(),
    };
    let data = AppData { admin, rules: Vec::new() };
    save_config_toml(&data);
    save_json(&data);
    data
}

fn save_json(data: &AppData) {
    let json_str = serde_json::to_string_pretty(data).unwrap();
    let _ = fs::write(DATA_FILE, json_str);
}

fn save_config_toml(data: &AppData) {
    let mut endpoints: Vec<RealmEndpoint> = data.rules.iter()
        .filter(|r| r.enabled)
        .map(|r| RealmEndpoint {
            name: r.name.clone(),
            listen: r.listen.clone(),
            remote: r.remote.clone(),
            r#type: "tcp+udp".to_string(),
        })
        .collect();
    if endpoints.is_empty() {
        endpoints.push(RealmEndpoint {
            name: "system-keepalive".to_string(),
            listen: "127.0.0.1:65534".to_string(),
            remote: "127.0.0.1:65534".to_string(),
            r#type: "tcp+udp".to_string(),
        });
    }
    let config = RealmConfig { endpoints };
    let toml_str = toml::to_string(&config).unwrap();
    let _ = fs::write(REALM_CONFIG, toml_str);
    let _ = Command::new("systemctl").arg("restart").arg("realm").status();
}

fn check_auth(cookies: &Cookies, state: &AppData) -> bool {
    cookies.get("auth_session").map(|c| c.value() == state.admin.pass_hash).unwrap_or(false)
}

// --- Iptables Helpers ---
fn extract_listen_port(listen: &str) -> Option<u16> {
    listen.trim().split(':').last()?.parse::<u16>().ok()
}

fn run_iptables(args: Vec<&str>) -> Result<(), String> {
    let status = Command::new("iptables").args(args).status().map_err(|e| e.to_string())?;
    if !status.success() { return Err("iptables failed".into()); }
    Ok(())
}

fn iptables_ensure_rule(port: u16, _quota: Option<u64>) -> Result<(), String> {
    // 简单做法：我们不使用复杂的 quota 模块，因为读取困难
    // 我们只需添加一个 ACCEPT 规则，然后通过 -v -x 读取该规则匹配的字节数即可
    // 1. 先删旧的
    let _ = iptables_del_rule(port);
    // 2. 添加 TCP 和 UDP 统计规则
    // iptables -I INPUT -p tcp --dport <port> -j ACCEPT
    run_iptables(vec!["-I", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "ACCEPT"])?;
    run_iptables(vec!["-I", "INPUT", "-p", "udp", "--dport", &port.to_string(), "-j", "ACCEPT"])?;
    Ok(())
}

fn iptables_del_rule(port: u16) -> Result<(), String> {
    // 尝试删除直到失败
    loop {
        let res1 = run_iptables(vec!["-D", "INPUT", "-p", "tcp", "--dport", &port.to_string(), "-j", "ACCEPT"]);
        let res2 = run_iptables(vec!["-D", "INPUT", "-p", "udp", "--dport", &port.to_string(), "-j", "ACCEPT"]);
        if res1.is_err() && res2.is_err() { break; }
    }
    Ok(())
}

fn iptables_reset_counter(port: u16) {
    // 重置计数器最简单的方法是删了重加
    let _ = iptables_del_rule(port);
    let _ = iptables_ensure_rule(port, None);
}

// --- Handlers ---

async fn index_page(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return axum::response::Redirect::to("/login").into_response(); }
    let html = DASHBOARD_HTML
        .replace("{{USER}}", &data.admin.username)
        .replace("{{BG_PC}}", &data.admin.bg_pc)
        .replace("{{BG_MOBILE}}", &data.admin.bg_mobile);
    Html(html).into_response()
}

async fn login_page(State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    let html = LOGIN_HTML.replace("{{BG_PC}}", &data.admin.bg_pc).replace("{{BG_MOBILE}}", &data.admin.bg_mobile);
    Html(html).into_response()
}
async fn login_action(cookies: Cookies, State(state): State<Arc<AppState>>, Form(form): Form<HashMap<String,String>>) -> Response {
    let data = state.data.lock().unwrap();
    if form.get("username").map(|s| s.as_str()) == Some(&data.admin.username) && form.get("password").map(|s| s.as_str()) == Some(&data.admin.pass_hash) {
        let mut cookie = Cookie::new("auth_session", data.admin.pass_hash.clone());
        cookie.set_path("/"); cookie.set_http_only(true); cookies.add(cookie);
        axum::response::Redirect::to("/").into_response()
    } else { StatusCode::UNAUTHORIZED.into_response() }
}
async fn logout_action(cookies: Cookies) -> Response {
    let mut cookie = Cookie::new("auth_session", ""); cookie.set_path("/"); cookies.remove(cookie);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn get_rules(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    
    // 获取实时流量
    let traffic_map = fetch_traffic_map();
    let rules_with_stats: Vec<RuleWithStats> = data.rules.iter().map(|r| {
        let mut used = 0;
        if let Some(port) = extract_listen_port(&r.listen) {
            used = *traffic_map.get(&port).unwrap_or(&0);
        }
        RuleWithStats { rule: r.clone(), used_bytes: used }
    }).collect();

    Json(serde_json::json!({"rules": rules_with_stats})).into_response()
}

#[derive(Deserialize)] struct AddRuleReq { name: String, listen: String, remote: String, expires_local: Option<String>, quota_gb: Option<f64> }
async fn add_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<AddRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let new_port = req.listen.split(':').last().unwrap_or("").trim();
    if data.rules.iter().any(|r| r.listen.split(':').last().unwrap_or("").trim() == new_port) {
        return Json(serde_json::json!({"status":"error","message":"端口已被占用"})).into_response();
    }
    
    let expires_at = req.expires_local.as_ref().and_then(|s| {
        Local.datetime_from_str(s, "%Y-%m-%dT%H:%M").ok().map(|dt| dt.with_timezone(&Utc).timestamp())
    });
    let quota_bytes = req.quota_gb.map(|gb| (gb * 1024.0 * 1024.0 * 1024.0) as u64);
    
    // 初始化 iptables
    if let Ok(p) = new_port.parse::<u16>() { let _ = iptables_ensure_rule(p, quota_bytes); }

    data.rules.push(Rule { 
        id: Uuid::new_v4().to_string(), name: req.name, listen: req.listen, remote: req.remote, enabled: true, expires_at, quota_bytes 
    });
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn toggle_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(r) = data.rules.iter_mut().find(|r| r.id == id) {
        r.enabled = !r.enabled;
        if let Some(port) = extract_listen_port(&r.listen) {
            if r.enabled { let _ = iptables_ensure_rule(port, r.quota_bytes); } else { let _ = iptables_del_rule(port); }
        }
        save_json(&data); save_config_toml(&data);
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn reset_traffic(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(r) = data.rules.iter().find(|r| r.id == id) {
        if let Some(port) = extract_listen_port(&r.listen) {
            iptables_reset_counter(port);
        }
    }
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn delete_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    if let Some(r) = data.rules.iter().find(|r| r.id == id) {
        if let Some(port) = extract_listen_port(&r.listen) { let _ = iptables_del_rule(port); }
    }
    data.rules.retain(|r| r.id != id);
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn delete_all_rules(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let _ = run_iptables(vec!["-F", "INPUT"]);
    data.rules.clear();
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

// 简化其余部分 (update_rule, batch_add, backup, restore 逻辑雷同，此处省略冗余代码以聚焦核心流量逻辑)
// 为保持脚本完整性，这里补充关键缺失的 update 和 batch

async fn update_rule(cookies: Cookies, State(state): State<Arc<AppState>>, Path(id): Path<String>, Json(req): Json<AddRuleReq>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let new_port = req.listen.split(':').last().unwrap_or("").trim();
    if data.rules.iter().any(|r| r.id != id && r.listen.split(':').last().unwrap_or("").trim() == new_port) {
        return Json(serde_json::json!({"status":"error","message":"端口被占"})).into_response();
    }
    let expires_at = req.expires_local.as_ref().and_then(|s| Local.datetime_from_str(s, "%Y-%m-%dT%H:%M").ok().map(|dt| dt.with_timezone(&Utc).timestamp()));
    let quota_bytes = req.quota_gb.map(|gb| (gb * 1024.0 * 1024.0 * 1024.0) as u64);

    if let Some(r) = data.rules.iter_mut().find(|r| r.id == id) {
        // 如果端口变了，删旧规则加新规则
        let old_port = extract_listen_port(&r.listen);
        let new_port_u16 = extract_listen_port(&req.listen);
        if old_port != new_port_u16 {
            if let Some(p) = old_port { let _ = iptables_del_rule(p); }
            if let Some(p) = new_port_u16 { let _ = iptables_ensure_rule(p, quota_bytes); }
        }
        r.name = req.name; r.listen = req.listen; r.remote = req.remote; r.expires_at = expires_at; r.quota_bytes = quota_bytes;
    }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn batch_add_rules(cookies: Cookies, State(state): State<Arc<AppState>>, Json(reqs): Json<Vec<AddRuleReq>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    for req in reqs {
        let p = req.listen.split(':').last().unwrap_or("").trim();
        if data.rules.iter().any(|r| r.listen.split(':').last().unwrap_or("").trim() == p) { continue; }
        let expires_at = req.expires_local.as_ref().and_then(|s| Local.datetime_from_str(s, "%Y-%m-%dT%H:%M").ok().map(|dt| dt.with_timezone(&Utc).timestamp()));
        let quota_bytes = req.quota_gb.map(|gb| (gb * 1024.0 * 1024.0 * 1024.0) as u64);
        if let Ok(port) = p.parse::<u16>() { let _ = iptables_ensure_rule(port, quota_bytes); }
        data.rules.push(Rule { id: Uuid::new_v4().to_string(), name: req.name, listen: req.listen, remote: req.remote, enabled: true, expires_at, quota_bytes });
    }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn update_account(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<HashMap<String,String>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.admin.username = req.get("username").unwrap().clone();
    if !req.get("password").unwrap().is_empty() { data.admin.pass_hash = req.get("password").unwrap().clone(); }
    save_json(&data); Json(serde_json::json!({"status":"ok"})).into_response()
}

async fn update_bg(cookies: Cookies, State(state): State<Arc<AppState>>, Json(req): Json<HashMap<String,String>>) -> Response {
    let mut data = state.data.lock().unwrap();
    if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    data.admin.bg_pc = req.get("bg_pc").unwrap().clone(); data.admin.bg_mobile = req.get("bg_mobile").unwrap().clone();
    save_json(&data); Json(serde_json::json!({"status":"ok"})).into_response()
}
async fn download_backup(cookies: Cookies, State(state): State<Arc<AppState>>) -> Response {
    let data = state.data.lock().unwrap(); if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let json = serde_json::to_string_pretty(&data.rules).unwrap();
    Response::builder().header("Content-Disposition","attachment;filename=backup.json").body(axum::body::Body::from(json)).unwrap()
}
async fn restore_backup(cookies: Cookies, State(state): State<Arc<AppState>>, Json(rules): Json<Vec<Rule>>) -> Response {
    let mut data = state.data.lock().unwrap(); if !check_auth(&cookies, &data) { return StatusCode::UNAUTHORIZED.into_response(); }
    let _ = run_iptables(vec!["-F", "INPUT"]);
    data.rules = rules; data.rules.retain(|r| r.name != "system-keepalive");
    for r in &data.rules { if let Some(p) = extract_listen_port(&r.listen) { let _ = iptables_ensure_rule(p, r.quota_bytes); } }
    save_json(&data); save_config_toml(&data);
    Json(serde_json::json!({"status":"ok"})).into_response()
}

// --- HTML Templates ---
const LOGIN_HTML: &str = r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login</title><style>body{background:url('{{BG_PC}}')no-repeat center/cover;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}')}}.box{background:rgba(255,255,255,0.4);backdrop-filter:blur(20px);padding:2rem;border-radius:20px;text-align:center}input{display:block;margin:10px 0;padding:10px;border-radius:8px;border:none;width:100%}button{padding:10px 20px;border-radius:8px;border:none;background:#3b82f6;color:#fff;cursor:pointer}</style></head><body><div class="box"><h2>Realm Panel</h2><form onsubmit="doL(event)"><input id="u" placeholder="User"><input id="p" type="password" placeholder="Pass"><button>Login</button></form></div><script>async function doL(e){e.preventDefault();await fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:`username=${document.getElementById('u').value}&password=${document.getElementById('p').value}`}).then(r=>{if(r.redirected)location.href='/';else alert('Error')})}</script></body></html>"#;

const DASHBOARD_HTML: &str = r#"
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Realm Panel</title><link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet"><style>:root{--primary:#3b82f6;--danger:#ef4444;--success:#10b981}body{font-family:sans-serif;margin:0;height:100vh;background:url('{{BG_PC}}') center/cover;display:flex;flex-direction:column;color:#333}@media(max-width:768px){body{background-image:url('{{BG_MOBILE}}')}}.nav{background:rgba(255,255,255,0.4);backdrop-filter:blur(10px);padding:1rem;display:flex;justify-content:space-between;align-items:center}.container{flex:1;padding:1rem;overflow:hidden;display:flex;flex-direction:column;max-width:1200px;margin:0 auto;width:100%}.card{background:rgba(255,255,255,0.5);backdrop-filter:blur(15px);border-radius:15px;padding:1rem;margin-bottom:1rem;box-shadow:0 4px 6px rgba(0,0,0,0.05)}.scroll{flex:1;overflow-y:auto}.input-group{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}input{padding:8px;border-radius:6px;border:1px solid #ddd}button{padding:8px 12px;border:none;border-radius:6px;cursor:pointer;color:#fff;font-weight:bold}.btn-blue{background:var(--primary)}.btn-red{background:var(--danger)}.btn-gray{background:#6b7280}table{width:100%;border-collapse:collapse}th{text-align:left;padding:10px;color:#555}td{padding:10px;border-top:1px solid rgba(0,0,0,0.05)}.progress-bar{height:6px;background:#e5e7eb;border-radius:3px;margin-top:5px;overflow:hidden}.progress-fill{height:100%;background:var(--primary);transition:width 0.3s}.status-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:5px}.online{background:var(--success)}.offline{background:#9ca3af}@media(max-width:700px){thead{display:none}tr{display:block;background:rgba(255,255,255,0.4);margin-bottom:10px;padding:10px;border-radius:10px}td{display:flex;justify-content:space-between;border:none;padding:5px 0}td:before{content:attr(data-label);color:#666}}</style></head>
<body>
<div class="nav"><b>Realm Panel</b><button class="btn-red" onclick="fetch('/logout',{method:'POST'}).then(()=>location.reload())"><i class="fas fa-sign-out-alt"></i></button></div>
<div class="container">
 <div class="card">
  <div class="input-group">
   <input id="n" placeholder="备注">
   <input id="l" placeholder="端口 (如 10000)">
   <input id="r" placeholder="目标 (IP:Port)">
   <input id="q" placeholder="配额GB (可选)">
   <input id="e" type="datetime-local">
   <button class="btn-blue" onclick="add()"><i class="fas fa-plus"></i> 添加</button>
  </div>
 </div>
 <div class="card scroll">
  <table><thead><tr><th>状态</th><th>备注</th><th>监听</th><th>目标</th><th>流量使用</th><th>到期</th><th style="text-align:right">操作</th></tr></thead><tbody id="list"></tbody></table>
 </div>
</div>
<script>
let rules=[];
const $=id=>document.getElementById(id);
function fmtBytes(bytes){if(bytes===0)return '0 B';const k=1024;const sizes=['B','KB','MB','GB','TB'];const i=Math.floor(Math.log(bytes)/Math.log(k));return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+' '+sizes[i]}
async function load(){const r=await fetch('/api/rules');if(r.status===401)location.reload();const d=await r.json();rules=d.rules;render()}
function render(){
 const t=$('list');t.innerHTML='';
 rules.forEach(item=>{
  const r=item.rule; const used=item.used_bytes;
  const row=document.createElement('tr');
  if(!r.enabled) row.style.opacity='0.6';
  
  let trafficHtml = fmtBytes(used);
  let percent = 0;
  if(r.quota_bytes){
   percent = Math.min(100, (used/r.quota_bytes)*100);
   trafficHtml += ` / ${fmtBytes(r.quota_bytes)}`;
   let color = percent>90?'#ef4444':(percent>70?'#f59e0b':'#3b82f6');
   trafficHtml += `<div class="progress-bar"><div class="progress-fill" style="width:${percent}%;background:${color}"></div></div>`;
  }
  
  const exp = r.expires_at ? new Date(r.expires_at*1000).toLocaleString() : '-';
  
  const html = `
   <td data-label="状态"><span class="status-dot ${r.enabled?'online':'offline'}"></span></td>
   <td data-label="备注">${r.name}</td>
   <td data-label="监听">${r.listen}</td>
   <td data-label="目标">${r.remote}</td>
   <td data-label="流量">${trafficHtml}</td>
   <td data-label="到期">${exp}</td>
   <td data-label="操作" style="text-align:right">
    <button class="btn-gray" onclick="tog('${r.id}')"><i class="fas ${r.enabled?'fa-pause':'fa-play'}"></i></button>
    <button class="btn-blue" onclick="reset('${r.id}')" title="重置流量"><i class="fas fa-sync"></i></button>
    <button class="btn-red" onclick="del('${r.id}')"><i class="fas fa-trash"></i></button>
   </td>
  `;
  row.innerHTML=html; t.appendChild(row);
 });
}
async function add(){
 const b={name:$('n').value,listen:$('l').value.includes(':')?$('l').value:'0.0.0.0:'+$('l').value,remote:$('r').value,expires_local:$('e').value||null,quota_gb:$('q').value?parseFloat($('q').value):null};
 await fetch('/api/rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
 $('n').value='';$('l').value='';$('r').value='';$('q').value='';load();
}
async function tog(id){await fetch(`/api/rules/${id}/toggle`,{method:'POST'});load()}
async function del(id){if(confirm('删?'))await fetch(`/api/rules/${id}`,{method:'DELETE'});load()}
async function reset(id){if(confirm('重置此规则流量统计?'))await fetch(`/api/rules/${id}/reset_traffic`,{method:'POST'});load()}
load(); setInterval(load, 5000); // Auto refresh
</script></body></html>
"#;
EOF

# 5. 编译安装
echo -e -n "${CYAN}>>> 编译面板程序 (Pro Max版)...${RESET}"
OS_ARCH=$(uname -m)
if [[ "$OS_ARCH" == "aarch64" ]]; then
    RUST_TRIPLE="aarch64-unknown-linux-gnu"
else
    RUST_TRIPLE="x86_64-unknown-linux-gnu"
fi

mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[target.$RUST_TRIPLE]
linker = "gcc"
rustflags = ["-C", "link-arg=-fuse-ld=bfd"]
EOF

cargo clean >/dev/null 2>&1
cargo build --release >/dev/null 2>&1 &
spinner $!

if [ -f "target/release/realm-panel" ]; then
    echo -e "${GREEN} [完成]${RESET}"
    mv target/release/realm-panel "$BINARY_PATH"
else
    echo -e "${RED} [失败] 编译出错${RESET}"
    exit 1
fi
rm -rf "$WORK_DIR"

# 6. 服务配置 (含 LimitNOFILE)
cat > /etc/systemd/system/realm-panel.service <<EOF
[Unit]
Description=Realm Panel Pro Max
After=network-online.target
Wants=network-online.target

[Service]
User=root
Environment="PANEL_USER=$DEFAULT_USER"
Environment="PANEL_PASS=$DEFAULT_PASS"
Environment="PANEL_PORT=$PANEL_PORT"
ExecStart=$BINARY_PATH
Restart=always
# 关键优化: 提高文件描述符限制，防止高并发断流
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable realm >/dev/null 2>&1
systemctl restart realm >/dev/null 2>&1
systemctl enable realm-panel >/dev/null 2>&1
systemctl restart realm-panel >/dev/null 2>&1
echo -e "${GREEN} [完成]${RESET}"

IP=$(curl -s4 ifconfig.me || hostname -I | awk '{print $1}')
echo -e ""
echo -e "${GREEN}==========================================${RESET}"
echo -e "${GREEN}✅ Realm 面板 (流量+配额+到期) 部署完毕！${RESET}"
echo -e "${GREEN}==========================================${RESET}"
echo -e "访问地址 : ${YELLOW}http://${IP}:${PANEL_PORT}${RESET}"
echo -e "默认密码 : ${YELLOW}${DEFAULT_PASS}${RESET}"
echo -e "功能说明 : 面板会自动每 5 秒刷新一次流量数据。"
echo -e "------------------------------------------"
