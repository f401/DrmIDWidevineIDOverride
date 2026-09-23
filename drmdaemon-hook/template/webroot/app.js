import { exec, toast } from './assets/kernelsu.js';

const CONFIG = '/data/adb/modules/drmdaemon-hook/config/targets.conf';
const KEY = 'deviceUniqueId';
const FORMAT = 'hex32';
const HEX32 = /^[0-9a-fA-F]{64}$/;
let rules = [];
const $ = (id) => document.getElementById(id);

function notify(message) {
  $('toast').textContent = message;
  $('toast').classList.add('show');
  setTimeout(() => $('toast').classList.remove('show'), 2200);
  try { toast(message); } catch (_) {}
}

async function shell(command) {
  const result = await exec(command, { env: { PATH: '/system/bin:/system/xbin:/vendor/bin' } });
  if (!result || result.errno !== 0) throw new Error((result && result.stderr) || `exit ${result?.errno}`);
  return result.stdout || '';
}

function parse(text) {
  return text.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
    if (line.startsWith('#')) return { comment: line };
    const parts = line.split('|');
    if (parts.length < 3) return { comment: `# ignored: ${line}` };
    return { version: parts[0].trim(), package: parts[1].trim(), key: parts[2].trim(), format: parts[3].trim(), value: parts.slice(4).join('|') };
  });
}

function serialize(items) {
  return items.map(item => item.comment ? item.comment : `v1|${item.package}|${KEY}|${FORMAT}|${item.value}`).join('\n') + '\n';
}

function render() {
  $('raw').value = serialize(rules);
  const visible = rules.filter(x => x.package && x.key === KEY && x.format === FORMAT);
  $('rules').innerHTML = visible.length ? visible.map((r, i) => `<div class="rule"><div><code>${escapeHtml(r.package)}</code><small>${escapeHtml(r.value)}</small></div><button data-index="${i}">编辑</button></div>`).join('') : '<div class="empty">暂无规则</div>';
  $('rules').querySelectorAll('button').forEach(button => button.addEventListener('click', () => {
    const r = visible[Number(button.dataset.index)]; $('package').value = r.package; $('deviceId').value = r.value;
  }));
}

function escapeHtml(value) { return String(value).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c])); }
function validPackage(value) { return /^[A-Za-z0-9_.$-]+$/.test(value); }
function validId(value) { return HEX32.test(value.trim()); }

async function load() {
  $('state').textContent = '读取中…';
  try { rules = parse(await shell(`cat '${CONFIG}'`)); render(); $('state').textContent = '已加载'; }
  catch (e) { $('state').textContent = '读取失败'; notify(`读取失败：${e.message}`); }
}

async function save() {
  const text = $('raw').value.endsWith('\n') ? $('raw').value : `${$('raw').value}\n`;
  const encoded = btoa(unescape(encodeURIComponent(text)));
  try {
    // Only the file is written here. The Zygisk Next companion process (running
    // as root) watches this file and pushes the new table to the injected
    // Widevine HAL over a unix socket, so the hook picks it up within ~1s.
    await shell(`printf '%s' '${encoded}' | base64 -d > '${CONFIG}' && chmod 0644 '${CONFIG}'`);
    rules = parse(text); render();
    $('state').textContent = '已保存';
    notify('配置已保存，companion 会自动下发（无需重启）');
  } catch (e) { notify(`保存失败：${e.message}`); }
}

$('add').addEventListener('click', () => {
  const packageName = $('package').value.trim(); const value = $('deviceId').value;
  if (!validPackage(packageName)) return notify('包名格式不正确');
  if (!validId(value)) return notify('设备 ID 必须是 64 位十六进制（32 字节）');
  rules = rules.filter(r => !(r.package === packageName && r.key === KEY));
  rules.push({ version: 'v1', package: packageName, key: KEY, format: FORMAT, value: value.trim().toLowerCase() }); render(); notify('规则已加入，点击保存配置');
});
$('remove').addEventListener('click', () => {
  const packageName = $('package').value.trim(); if (!validPackage(packageName)) return notify('请输入要删除的包名');
  rules = rules.filter(r => !(r.package === packageName && r.key === KEY)); render(); notify('规则已删除，点击保存配置');
});
$('reload').addEventListener('click', load); $('save').addEventListener('click', save);
$('logs').addEventListener('click', async () => { try { $('log').textContent = await shell("logcat -d -s drmdaemon-hook:I *:S | tail -80"); } catch (e) { $('log').textContent = e.message; } });
load();
