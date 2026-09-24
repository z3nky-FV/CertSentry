'use client';

import React, { useEffect, useState } from 'react';
import { ShieldCheck, Radar, Download, Loader2, ChevronLeft, ChevronRight, ArrowUpDown } from 'lucide-react';

const API = '/api/v1';
const PAGE_SIZE = 25;
const STATUSES = ['', 'OK', 'INFORMATION', 'WARNING', 'CRITICAL', 'EXPIRED'];
type RiskFactor = { name: string; score: number; description: string; recommendation: string };
type CertificateChange = {
  detected_at: string; old_thumbprint: string | null; new_thumbprint: string;
  old_status: string | null; new_status: string; old_risk_score: number; new_risk_score: number;
  differences: { field: string; old: unknown; new: unknown }[]; acknowledged: boolean;
};
type Certificate = {
  id: number; hostname: string; port: number; common_name: string | null; sans: string[]; issuer: string | null;
  thumbprint_sha256: string; valid_from: string | null; valid_to: string | null; days_left: number;
  is_self_signed: boolean; is_chain_valid: boolean; is_hostname_match: boolean; is_weak_crypto: boolean; status: string;
  risk_score: number; risk_factors: RiskFactor[]; criticality: string; owner: string; scanned_at: string;
  baseline_thumbprint?: string; change_count: number; change_pending: boolean; last_change: CertificateChange | null;
};
type ScanError = { hostname: string; port: number; error: string | null };

const changeValue = (value: unknown) => Array.isArray(value) ? value.join(', ') :
  typeof value === 'boolean' ? (value ? 'Да' : 'Нет') : value == null ? '—' : String(value);
const issuerLabel = (issuer: string | null) => {
  if (!issuer) return '—';
  const organization = issuer.match(/(?:^|,\s*)O=([^,]+)/)?.[1];
  const commonName = issuer.match(/(?:^|,\s*)CN=([^,]+)/)?.[1];
  return (organization || commonName || issuer).trim();
};

const fetcher = async (url: string, init?: RequestInit) => {
  const res = await fetch(url, init);
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    const text = await res.text();
    try { const body = JSON.parse(text); message = body.detail || body.message || message; }
    catch { message = text || message; }
    throw new Error(message);
  }
  return res.json();
};

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<any>(null);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [input, setInput] = useState('');
  const [crit, setCrit] = useState('MEDIUM');
  const [owner, setOwner] = useState('');
  const [statusF, setStatusF] = useState('');
  const [changesOnly, setChangesOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState('days_left');
  const [sortOrder, setSortOrder] = useState('asc');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [scanErrors, setScanErrors] = useState<ScanError[]>([]);
  const [acknowledging, setAcknowledging] = useState<number | null>(null);

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(async () => {
      setLoading(true);
      setError('');
      try {
        const q = new URLSearchParams({
          page: page.toString(), page_size: PAGE_SIZE.toString(), sort_by: sort,
          sort_order: sortOrder, query: search,
        });
        if (statusF) q.set('status', statusF);
        if (changesOnly) q.set('changed_only', 'true');
        const [m, c] = await Promise.all([
          fetcher(`${API}/metrics/summary`), fetcher(`${API}/certificates?${q.toString()}`),
        ]);
        if (active) {
          setMetrics(m); setCerts(c.items); setTotal(c.total); setTotalPages(c.total_pages);
        }
      } catch (e) {
        if (active) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (active) setLoading(false);
      }
    }, search ? 250 : 0);
    return () => { active = false; window.clearTimeout(timer); };
  }, [page, sort, sortOrder, statusF, search, changesOnly]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    const targets = input.split(/[\n,;]+/).map(x => x.trim()).filter(Boolean);
    if (!targets.length) return;
    setLoading(true); setError(''); setNotice(''); setScanErrors([]);
    try {
      const result = await fetcher(`${API}/scan/run`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets, criticality: crit, owner: owner.trim() }),
      });
      setScanErrors(result.errors || []);
      setNotice(`Сканирование завершено: сертификатов добавлено или обновлено ${result.successful}; изменений сертификата обнаружено ${result.changes_detected}; ошибок ${result.failed}.`);
      setInput(''); setPage(1);
      const q = new URLSearchParams({ page: '1', page_size: PAGE_SIZE.toString(), sort_by: sort, sort_order: sortOrder });
      if (statusF) q.set('status', statusF);
      if (search) q.set('query', search);
      if (changesOnly) q.set('changed_only', 'true');
      const [m, c] = await Promise.all([fetcher(`${API}/metrics/summary`), fetcher(`${API}/certificates?${q.toString()}`)]);
      setMetrics(m); setCerts(c.items); setTotal(c.total); setTotalPages(c.total_pages);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  };

  const acknowledgeChange = async (e: React.MouseEvent, certificate: Certificate) => {
    e.stopPropagation(); setAcknowledging(certificate.id); setError('');
    try {
      const result = await fetcher(`${API}/certificates/${certificate.id}/acknowledge-change`, { method: 'POST' });
      setCerts(items => changesOnly ? items.filter(item => item.id !== certificate.id) :
        items.map(item => item.id === certificate.id ? result.certificate : item));
      if (changesOnly) {
        const remaining = Math.max(0, total - 1);
        const pages = Math.ceil(remaining / PAGE_SIZE);
        setTotal(remaining); setTotalPages(pages);
        if (page > Math.max(1, pages)) setPage(Math.max(1, pages));
      }
      setMetrics((value: any) => value ? { ...value, pending_changes: Math.max(0, value.pending_changes - 1) } : value);
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setAcknowledging(null); }
  };

  const setSortField = (field: string) => {
    if (sort === field) setSortOrder(order => order === 'asc' ? 'desc' : 'asc');
    else { setSort(field); setSortOrder(field === 'risk_score' ? 'desc' : 'asc'); }
    setPage(1);
  };
  const statusColor = (s: string) => s === 'OK' ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' :
    s === 'INFORMATION' ? 'text-blue-400 bg-blue-500/10 border-blue-500/30' :
    s === 'WARNING' ? 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30' :
    s === 'CRITICAL' ? 'text-red-400 bg-red-500/10 border-red-500/30' :
    'text-rose-300 bg-rose-500/10 border-rose-500/30';
  const formatDate = (iso: string | null) => iso ? new Date(iso).toLocaleDateString('ru-RU') : '—';

  const kpis = metrics ? [
    ['Сертификаты', metrics.total_certificates], ['Средний риск', `${metrics.overall_risk_score}/100`],
    ['Критичные / истекли', `${metrics.critical_count} / ${metrics.expired_count}`],
    ['Истекают за 14 дней', metrics.expiring_soon], ['Self-signed', metrics.self_signed_count],
    ['Средний остаток', `${metrics.avg_days_left} дн.`], ['Изменения на проверку', metrics.pending_changes],
  ] : [];
  const columns = [
    ['hostname', 'Service'], ['issuer', 'Certificate'],
    ['valid_to', 'Expiration'], ['days_left', 'Days Left'],
  ];

  return (
    <main className="min-h-screen p-4 md:p-6 max-w-7xl mx-auto space-y-5">
      <header className="flex items-center gap-3 pb-4 border-b border-slate-800">
        <ShieldCheck className="w-8 h-8 text-blue-500" />
        <div><h1 className="text-xl font-bold">CertSentry</h1><p className="text-xs text-slate-400">Certificate Radar · мониторинг рисков TLS-сертификатов</p></div>
        <span className="ml-auto text-xs text-slate-400">{loading ? 'Обновление…' : `${total} сервисов`}</span>
      </header>

      {error && <div role="alert" className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">Не удалось выполнить запрос: {error}</div>}
      {notice && <div role="status" className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-200">{notice}</div>}

      <section className="grid lg:grid-cols-2 gap-4">
        {metrics && <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {kpis.map(([label, value]) => <div key={label} className="bg-slate-800/40 p-3 rounded-xl border border-slate-700/50">
            <div className="text-xs text-slate-400 mb-1">{label}</div><div className="text-xl font-bold">{value}</div>
          </div>)}
          <div className="col-span-2 sm:col-span-3 bg-slate-800/40 px-3 py-2 rounded-xl border border-slate-700/50 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-300">
            {Object.entries(metrics.status_distribution || {}).map(([s, n]) => <span key={s}>{s}: <b>{n as number}</b></span>)}
          </div>
        </div>}

        <form onSubmit={handleScan} className="bg-slate-800/40 p-4 rounded-xl border border-slate-700/50 flex flex-col gap-3">
          <div className="text-sm font-medium flex items-center gap-2"><Radar className="w-4 h-4" /> Новое сканирование</div>
          <div className="flex flex-col sm:flex-row gap-2">
            <input aria-label="Ответственный" className="bg-slate-900 border border-slate-700 rounded px-2 py-2 text-sm sm:w-1/3 focus:outline-none focus:border-blue-500"
              placeholder="Владелец сервиса" value={owner} onChange={e => setOwner(e.target.value)} disabled={loading} maxLength={200} />
            <select aria-label="Критичность сервиса" className="bg-slate-900 border border-slate-700 rounded px-2 py-2 text-sm flex-1 focus:outline-none focus:border-blue-500"
              value={crit} onChange={e => setCrit(e.target.value)} disabled={loading}>
              <option value="LOW">Низкая критичность</option><option value="MEDIUM">Средняя критичность</option>
              <option value="HIGH">Высокая критичность</option><option value="CRITICAL">Критичный сервис</option>
            </select>
          </div>
          <textarea aria-label="Цели сканирования" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm min-h-24 resize-y focus:outline-none focus:border-blue-500"
            placeholder={'Домен, IP, CIDR или HTTPS URL (по одному на строку)\nexample.com\n10.0.0.0/24\nhttps://portal.example.com:8443'}
            value={input} onChange={e => setInput(e.target.value)} disabled={loading} />
          <div className="flex justify-between items-center gap-2 text-xs text-slate-400">
            <span>Поддерживается до 1024 адресов за запуск. Повторное сканирование обновляет инвентарную запись.</span>
            <button disabled={loading || !input.trim()} className="shrink-0 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 px-4 py-2 rounded text-sm font-medium flex items-center gap-2 transition-colors">
              {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Сканирование</> : 'Сканировать'}
            </button>
          </div>
        </form>
      </section>

      {scanErrors.length > 0 && <section className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-3">
        <h2 className="font-medium text-amber-200 text-sm mb-2">Не удалось получить сертификат ({scanErrors.length})</h2>
        <ul className="max-h-40 overflow-auto space-y-1 text-xs text-slate-300">
          {scanErrors.map((item, i) => <li key={`${item.hostname}:${item.port}:${i}`}><code>{item.hostname}:{item.port}</code> — {item.error || 'Неизвестная ошибка'}</li>)}
        </ul>
      </section>}

      <section className="bg-slate-800/40 rounded-xl border border-slate-700/50 overflow-hidden">
        <div className="p-3 md:p-4 border-b border-slate-700/50">
          <h2 className="font-semibold">Сертификаты</h2>
          <p className="text-xs text-slate-400 mt-1">В столбце Certificate указан центр, выдавший сертификат (Issuer / CA); полное имя и детали доступны при раскрытии строки.</p>
        </div>
        <div className="p-3 md:p-4 flex flex-col lg:flex-row gap-3 justify-between lg:items-center border-b border-slate-700/50">
          <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
            <input aria-label="Поиск сертификатов" type="search" placeholder="Сервис, владелец, Issuer, статус, дата…" value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }} className="bg-slate-900 border border-slate-700 rounded px-2 py-2 text-sm focus:outline-none w-full sm:w-64" />
            <div className="flex flex-wrap gap-1">
              {STATUSES.map(s => <button key={s || 'all'} onClick={() => { setStatusF(s); setPage(1); }}
                aria-pressed={statusF === s} className={`px-2 py-1.5 rounded text-xs transition-colors ${statusF === s ? 'bg-blue-600 text-white' : 'bg-slate-700/50 hover:bg-slate-600'}`}>{s || 'Все'}</button>)}
              <button onClick={() => { setChangesOnly(value => !value); setPage(1); }} aria-pressed={changesOnly}
                className={`px-2 py-1.5 rounded text-xs transition-colors ${changesOnly ? 'bg-orange-600 text-white' : 'bg-slate-700/50 hover:bg-slate-600'}`}>Изменения</button>
            </div>
          </div>
          <a href={`${API}/reports/export`} className="flex gap-2 items-center justify-center text-slate-200 hover:text-white text-xs bg-slate-700/50 px-3 py-2 rounded"><Download className="w-3.5 h-3.5" /> Скачать CSV</a>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-slate-900/40 text-slate-400 text-xs">
              <tr>{columns.map(([field, label]) => <th key={field} scope="col" className="p-3 font-medium">
                <button className="inline-flex items-center gap-1 hover:text-white" onClick={() => setSortField(field)}>{label}<ArrowUpDown className={`w-3 h-3 ${sort === field ? 'text-blue-400' : ''}`} />{sort === field && <span>{sortOrder === 'asc' ? '↑' : '↓'}</span>}</button>
              </th>)}</tr>
            </thead>
            <tbody className="divide-y divide-slate-700/30">
              {certs.length === 0 ? <tr><td colSpan={4} className="p-8 text-center text-slate-400">{loading ? 'Загрузка…' : 'Сертификаты не найдены. Запустите сканирование или измените фильтр.'}</td></tr> : certs.map(c => {
                const rowKey = `${c.hostname}:${c.port}`;
                return <React.Fragment key={rowKey}>
                <tr className="hover:bg-slate-700/20 cursor-pointer transition-colors" onClick={() => setExpanded(expanded === rowKey ? null : rowKey)} aria-expanded={expanded === rowKey}>
                  <td className="p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono">{c.hostname}:{c.port}</span>
                      <span aria-label={`Статус: ${c.status}`} className={`px-2 py-0.5 rounded text-xs border ${statusColor(c.status)}`}>{c.status}</span>
                    </div>
                  </td>
                  <td className="p-3 max-w-[220px] truncate text-slate-300" title={c.issuer || ''}>{issuerLabel(c.issuer)}</td>
                  <td className="p-3">{formatDate(c.valid_to)}</td>
                  <td className="p-3">{c.days_left}</td>
                </tr>
                {expanded === rowKey && <tr className="bg-slate-900/40 text-xs"><td colSpan={4} className="p-4 whitespace-normal">
                  <div className="grid md:grid-cols-2 gap-2 text-slate-300">
                    <div><span className="text-slate-400">CN:</span> {c.common_name || '—'}</div>
                    <div className="break-all"><span className="text-slate-400">SAN:</span> {c.sans?.length ? c.sans.join(', ') : '—'}</div>
                    <div><span className="text-slate-400">Владелец:</span> {c.owner || '—'}</div>
                    <div><span className="text-slate-400">Критичность:</span> {c.criticality}</div>
                    <div><span className="text-slate-400">Статус:</span> <span className={`px-2 py-0.5 rounded text-xs border ${statusColor(c.status)}`}>{c.status}</span></div>
                    <div><span className="text-slate-400">Risk Score:</span> {c.risk_score}/100</div>
                    <div><span className="text-slate-400">Цепочка доверия:</span> {c.is_chain_valid ? 'валидна' : 'ошибка проверки'}</div>
                    <div><span className="text-slate-400">DNS соответствует:</span> {c.is_hostname_match ? 'да' : 'нет'}</div>
                    <div><span className="text-slate-400">Self-signed:</span> {c.is_self_signed ? 'да' : 'нет'}</div>
                    <div><span className="text-slate-400">Слабая криптография:</span> {c.is_weak_crypto ? 'да' : 'нет'}</div>
                    <div><span className="text-slate-400">Проверено:</span> {c.scanned_at ? new Date(c.scanned_at).toLocaleString('ru-RU') : '—'}</div>
                    <div className="md:col-span-2 break-all"><span className="text-slate-400">SHA-256:</span> {c.thumbprint_sha256 || '—'}</div>
                    <div className="md:col-span-2 break-all"><span className="text-slate-400">Issuer (полное имя):</span> {c.issuer || '—'}</div>
                    <div><span className="text-slate-400">Изменение:</span> {c.change_pending ? 'Требует проверки' : c.change_count > 0 ? 'Проверено' : 'Базовая версия'}</div>
                    {c.last_change && <section className="md:col-span-2 mt-2 rounded-lg border border-orange-400/30 bg-orange-500/5 p-3 space-y-2">
                      <div className="flex flex-wrap justify-between gap-2 items-start">
                        <div><h3 className="font-semibold text-orange-200">Изменение сертификата №{c.change_count}</h3>
                          <p className="text-slate-400 mt-1">Обнаружено: {new Date(c.last_change.detected_at).toLocaleString('ru-RU')}</p></div>
                        <span className={c.last_change.acknowledged ? 'text-emerald-400' : 'text-orange-200'}>{c.last_change.acknowledged ? 'Отмечено проверенным' : 'Требует проверки'}</span>
                      </div>
                      <div className="break-all"><span className="text-slate-400">Предыдущий thumbprint:</span> {c.last_change.old_thumbprint || '—'}</div>
                      <div className="break-all"><span className="text-slate-400">Текущий thumbprint:</span> {c.last_change.new_thumbprint || '—'}</div>
                      <div className="text-slate-300">Статус: {c.last_change.old_status || '—'} → {c.last_change.new_status}; риск: {c.last_change.old_risk_score} → {c.last_change.new_risk_score}</div>
                      <ul className="list-disc pl-5 text-slate-300">{c.last_change.differences.map((diff, i) => <li key={`${diff.field}:${i}`}>
                        {diff.field}: {changeValue(diff.old)} → {changeValue(diff.new)}
                      </li>)}</ul>
                      {c.change_pending && <button disabled={acknowledging === c.id} onClick={e => acknowledgeChange(e, c)}
                        className="rounded bg-orange-600 hover:bg-orange-500 disabled:opacity-50 px-3 py-1.5 text-white text-xs">
                        {acknowledging === c.id ? 'Сохраняю…' : 'Отметить изменение проверенным'}
                      </button>}
                    </section>}
                    {c.risk_factors.map((f, i) => <div key={`${f.name}:${i}`} className="md:col-span-2 border-t border-slate-700/50 pt-2">
                      <div className="text-rose-300">+{f.score} — {f.description}</div><div className="text-slate-400 mt-1">Рекомендация: {f.recommendation}</div>
                    </div>)}
                  </div>
                </td></tr>}
              </React.Fragment>;
              })}
            </tbody>
          </table>
        </div>
        <footer className="p-3 border-t border-slate-700/50 flex justify-between items-center text-sm text-slate-400">
          <span>Записей: {total}</span><div className="flex items-center gap-3">
            <button aria-label="Предыдущая страница" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1} className="hover:text-white disabled:opacity-30"><ChevronLeft className="w-4 h-4" /></button>
            <span>Страница {page} из {Math.max(1, totalPages)}</span>
            <button aria-label="Следующая страница" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages} className="hover:text-white disabled:opacity-30"><ChevronRight className="w-4 h-4" /></button>
          </div>
        </footer>
      </section>
    </main>
  );
}
