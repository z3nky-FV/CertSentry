import Link from 'next/link';
import { ArrowDown, ArrowRight, Activity, Fingerprint, GitCompareArrows, ShieldCheck } from 'lucide-react';

const features = [
  {
    number: '01',
    icon: Fingerprint,
    title: 'Инвентарь TLS',
    description: 'Собирает сертификаты сайтов и сервисов в одном понятном списке.',
  },
  {
    number: '02',
    icon: Activity,
    title: 'Оценка риска',
    description: 'Находит истечение, ошибки доверия, несовпадение имени и слабую криптографию.',
  },
  {
    number: '03',
    icon: GitCompareArrows,
    title: 'ChangeGuard',
    description: 'Сравнивает сертификаты между проверками и показывает, что изменилось.',
  },
];

const steps = [
  { number: '01', title: 'Добавьте сервисы', text: 'Укажите домены или IP-адреса — CertSentry проверит доступные TLS-сертификаты.' },
  { number: '02', title: 'Поймите риск', text: 'Получите статусы, оценку риска и рекомендации по каждому найденному сертификату.' },
  { number: '03', title: 'Следите за изменениями', text: 'При повторной проверке ChangeGuard покажет, что изменилось и требует внимания.' },
];

export default function HomePage() {
  return (
    <main className="landing-page">
      <div className="landing-orb landing-orb-right" aria-hidden="true" />
      <div className="landing-orb landing-orb-bottom" aria-hidden="true" />

      <header className="landing-header">
        <Link href="/" className="landing-brand" aria-label="CertSentry — главная">
          <span className="landing-brand-icon"><ShieldCheck size={19} strokeWidth={1.8} /></span>
          <span>CertSentry</span>
        </Link>
        <nav className="landing-nav" aria-label="Основная навигация">
          <a href="#features">Возможности</a>
          <Link href="/dashboard" className="landing-nav-cta">Открыть Dashboard <ArrowRight size={15} /></Link>
        </nav>
      </header>

      <section className="landing-hero" aria-labelledby="hero-title">
        <div className="hero-eyebrow"><span className="hero-live-dot" /> TLS GOVERNANCE &amp; MONITORING</div>
        <h1 id="hero-title" className="hero-title">CertSentry<span>.</span></h1>
        <p className="hero-description">
          Автоматизированный мониторинг цифровых сертификатов.<br className="hidden sm:block" />
          Понятная оценка рисков и контроль изменений инфраструктуры.
        </p>
        <Link href="/dashboard" className="hero-button">
          Перейти в Dashboard <ArrowRight size={18} />
        </Link>
        <a className="hero-scroll" href="#features"><span>Знакомство с проектом</span><ArrowDown size={14} /></a>
        <div className="hero-index" aria-hidden="true"><span /> CERTIFICATE RADAR · 01 / 03</div>
      </section>

      <section className="landing-features" id="features" aria-labelledby="features-title">
        <div className="features-heading">
          <p className="section-eyebrow">ЧТО ДЕЛАЕТ CERTSENTRY</p>
          <h2 id="features-title">Состояние сертификатов —<br className="hidden sm:block" /> под контролем.</h2>
        </div>
        <div className="feature-grid">
          {features.map(({ number, icon: Icon, title, description }) => (
            <article className="feature-card" key={number}>
              <div className="feature-card-top"><span>{number}</span><Icon size={20} strokeWidth={1.7} /></div>
              <h3>{title}</h3>
              <p>{description}</p>
              <span className="feature-card-line" />
            </article>
          ))}
        </div>
        <div className="features-bottom">
          <p>CertSentry проверяет сертификаты и помогает команде вовремя заметить проблему.</p>
          <Link href="/dashboard">Посмотреть Dashboard <ArrowRight size={16} /></Link>
        </div>
      </section>

      <section className="landing-story" aria-labelledby="story-title">
        <div className="story-intro">
          <p className="section-eyebrow">ОТ ПРОВЕРКИ К ДЕЙСТВИЮ</p>
          <h2 id="story-title">Сначала заметить.<br />Затем разобраться.</h2>
          <p className="story-description">
            Истёкший сертификат, недоверенная цепочка или имя, которое не совпадает с сайтом,
            могут нарушить подключение. CertSentry собирает такие сигналы в одном месте,
            чтобы команда могла разобраться до того, как проблема застанет пользователей.
          </p>
        </div>
        <div className="story-steps">
          {steps.map(({ number, title, text }) => (
            <article className="story-step" key={number}>
              <span className="story-step-number">{number}</span>
              <div><h3>{title}</h3><p>{text}</p></div>
              <span className="story-step-mark" aria-hidden="true">↗</span>
            </article>
          ))}
        </div>
        <div className="story-note">
          <ShieldCheck size={19} />
          <p>CertSentry работает в режиме чтения: он проверяет сертификат, который сервис предъявляет, и не меняет настройки серверов.</p>
        </div>
      </section>

      <section className="landing-last-call">
        <span className="section-eyebrow">CERTIFICATE RADAR</span>
        <h2>Начните с одного сканирования.</h2>
        <p>Откройте Dashboard, добавьте тестовый сервис и посмотрите его состояние.</p>
        <Link href="/dashboard" className="hero-button">Открыть Dashboard <ArrowRight size={17} /></Link>
      </section>

      <footer className="landing-footer">
        <Link href="/" className="landing-brand"><span className="landing-brand-icon"><ShieldCheck size={16} /></span><span>CertSentry</span></Link>
        <span>Certificate Radar · Hackathon</span>
      </footer>
    </main>
  );
}
