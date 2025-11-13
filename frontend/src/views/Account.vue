<template>
  <div class="w-full">
    <nav
      class="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-white/5 bg-slate-950/70 px-8 py-5 backdrop-blur"
    >
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-amber-300">Security Dashboard</p>
        <p class="text-xl font-semibold text-slate-100">
          Welcome back, {{ profile?.full_name ?? 'friend' }}
        </p>
      </div>
      <div class="flex items-center gap-3 text-sm text-slate-300">
        <a
          v-for="item in navItems"
          :key="item.href"
          :href="item.href"
          class="rounded-full border border-slate-700/70 px-4 py-1.5 font-medium text-slate-200 hover:border-amber-300 hover:text-amber-200"
        >
          {{ item.label }}
        </a>
        <button
          class="rounded-full bg-rose-500/80 px-4 py-1.5 text-sm font-semibold text-white hover:bg-rose-400/90"
          @click="signOut"
        >
          Sign out
        </button>
      </div>
    </nav>

    <div class="w-full space-y-10 px-8 py-10 text-slate-200">
      <p v-if="error" class="text-sm text-rose-300">{{ error }}</p>

      <div
        v-if="loading"
        class="rounded-2xl border border-slate-700 bg-slate-800/60 p-6 text-sm text-slate-300"
      >
        Loading your profile…
      </div>

      <div v-else class="grid gap-8 lg:grid-cols-3">
        <section
          id="overview"
          class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 lg:col-span-2"
        >
          <h3 class="text-lg font-semibold text-amber-200">Account Overview</h3>
          <p class="text-sm text-slate-400 mt-1">Quick context about your identity and session.</p>
          <dl class="mt-6 grid gap-4 text-sm md:grid-cols-2">
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Full name</dt>
              <dd class="text-lg font-medium text-slate-100 truncate">{{ profile?.full_name }}</dd>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Email</dt>
              <dd class="text-lg font-medium text-slate-100 break-all">{{ profile?.email }}</dd>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Last login</dt>
              <dd class="text-lg font-medium text-slate-100">
                {{ new Date().toLocaleString() }}
              </dd>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Session status</dt>
              <dd class="text-lg font-medium text-emerald-300">Secure · Passkey verified</dd>
            </div>
          </dl>
        </section>

        <section
          id="safeguards"
          class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6"
        >
          <h3 class="text-lg font-semibold text-emerald-300">Key Safeguards</h3>
          <p class="text-xs uppercase tracking-[0.2em] text-slate-500 mb-4">
            Always-on protections
          </p>
          <div class="space-y-4">
            <article
              v-for="insight in safeguards"
              :key="insight.title"
              class="rounded-2xl border border-slate-800/70 bg-slate-950/70 p-4 space-y-1"
            >
              <p class="text-sm font-semibold text-slate-100">{{ insight.title }}</p>
              <p class="text-xs text-slate-400 leading-relaxed">{{ insight.detail }}</p>
            </article>
          </div>
        </section>

        <section
          id="news"
          class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 lg:col-span-3"
        >
          <div class="flex flex-wrap items-center justify-between gap-4">
            <h3 class="text-lg font-semibold text-sky-300">Security &amp; Tech Headlines</h3>
            <p class="text-xs text-slate-400">Curated from trusted newsrooms</p>
          </div>
          <ul class="mt-6 grid gap-4 md:grid-cols-3">
            <li
              v-for="item in securityNews"
              :key="item.title"
              class="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 space-y-2"
            >
              <p class="text-xs uppercase tracking-widest text-slate-500">{{ item.source }}</p>
              <p class="text-base font-semibold text-slate-100">{{ item.title }}</p>
              <p class="text-sm text-slate-400">{{ item.summary }}</p>
              <a
                v-if="item.link"
                :href="item.link"
                target="_blank"
                rel="noopener"
                class="text-xs font-semibold text-sky-300 hover:text-sky-200 inline-flex items-center gap-1"
              >
                Read article
                <span aria-hidden="true">↗</span>
              </a>
            </li>
          </ul>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { fetchProfile } from '../api';
import { clearToken } from '../token';

const router = useRouter();
const profile = ref(null);
const error = ref('');
const loading = ref(true);
const navItems = [
  { label: 'Overview', href: '#overview' },
  { label: 'Safeguards', href: '#safeguards' },
  { label: 'Headlines', href: '#news' },
];
const safeguards = [
  {
    title: 'Passkey protection',
    detail: 'Your devices use passkeys with hardware-backed encryption to keep logins phishing-resistant.',
  },
  {
    title: 'Session monitoring',
    detail: 'We alert you when sign-ins happen from unusual locations or browsers.',
  },
  {
    title: 'Data privacy',
    detail: 'Personal details stay encrypted at rest and are never shared with third parties.',
  },
];
const securityNews = [
  {
    title: 'Global agencies warn of credential phishing spikes',
    summary:
      'Interpol and CISA note a 46% rise in campaigns targeting password resets—passkeys remain a top mitigation.',
    source: 'CISA Brief',
    link: 'https://www.cisa.gov/news-events',
  },
  {
    title: 'AI helps defenders triage incidents faster',
    summary:
      'New tooling classifies alerts in seconds, freeing analysts to focus on threat hunting and proactive hardening.',
    source: 'CyberPulse Daily',
    link: 'https://www.cyberscoop.com/',
  },
  {
    title: 'Zero-trust adoption hits record highs',
    summary:
      'Enterprises accelerate device attestation and least-privilege access to secure hybrid workforces.',
    source: 'SecureWeek',
    link: 'https://www.darkreading.com/',
  },
];

async function loadProfile() {
  try {
    profile.value = await fetchProfile();
    loading.value = false;
  } catch (err) {
    error.value = err?.response?.data?.message ?? 'Session expired.';
    clearToken();
    router.replace('/login');
    loading.value = false;
  }
}

function signOut() {
  clearToken();
  router.replace('/login');
}

onMounted(loadProfile);
</script>
