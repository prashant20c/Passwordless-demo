<template>
  <div class="w-full">
    <nav
      class="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-white/5 bg-slate-950/70 px-8 py-5 backdrop-blur"
    >
      <div>
        <p class="text-xs uppercase tracking-[0.3em] text-amber-300">Security Dashboard</p>
        <p class="text-xl font-semibold text-slate-100">
          Welcome back, {{ greetingName }}
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-3 text-sm text-slate-300">
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

      <div v-else class="space-y-8">
        <section
          id="overview"
          class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 space-y-6"
        >
          <div class="flex flex-wrap items-start justify-between gap-6">
            <div>
              <p class="text-xs uppercase tracking-[0.3em] text-amber-300">Welcome</p>
              <h3 class="mt-2 text-3xl font-semibold text-slate-50">
                Hello, {{ greetingName }}
              </h3>
              <p class="mt-2 text-sm text-slate-400">
                You are logged in using Trustlogin. Approve new logins from your linked device anytime.
              </p>
            </div>
            <div class="rounded-2xl border border-slate-800 bg-slate-950/60 px-4 py-3 text-right text-sm">
              <p class="text-slate-500">Account email</p>
              <p class="text-lg font-semibold text-slate-100 break-all">{{ profile?.email }}</p>
              <p class="mt-1 text-xs text-slate-500">
                Session ID
                <span class="font-mono text-slate-300">{{ profile?.session_id ?? '—' }}</span>
              </p>
            </div>
          </div>
          <dl class="grid gap-4 text-sm md:grid-cols-2">
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Full name</dt>
              <dd class="text-lg font-medium text-slate-100 truncate">{{ profile?.full_name }}</dd>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Email</dt>
              <dd class="text-lg font-medium text-slate-100 break-all">{{ profile?.email }}</dd>
            </div>
            <div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
              <dt class="text-slate-400">Last authenticated</dt>
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

        <div class="grid gap-8 lg:grid-cols-3">
          <section
            id="sessions"
            class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 lg:col-span-2"
          >
            <div class="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h3 class="text-lg font-semibold text-amber-200">Active Sessions</h3>
                <p class="text-sm text-slate-400">
                  Below is a list of browsers currently signed in with your account.
                </p>
              </div>
              <button
                class="rounded-full border border-amber-300/50 px-4 py-1.5 text-sm font-semibold text-amber-200 hover:bg-amber-300/10 disabled:opacity-70"
                :disabled="sessionsLoading"
                @click="refreshSessions"
              >
                {{ sessionsLoading ? 'Refreshing…' : 'Refresh' }}
              </button>
            </div>
            <p v-if="sessionsError" class="mt-4 text-sm text-rose-300">{{ sessionsError }}</p>
            <div
              v-if="sessionsLoading"
              class="mt-6 rounded-2xl border border-slate-800 bg-slate-950/60 px-5 py-4 text-sm text-slate-400"
            >
              Loading active sessions…
            </div>
            <div v-else>
              <div
                v-if="sessions.length"
                class="mt-6 overflow-x-auto rounded-2xl border border-slate-800/70 bg-slate-950/40"
              >
                <table class="min-w-full divide-y divide-slate-800 text-sm">
                  <thead class="bg-slate-950/70 text-xs uppercase tracking-widest text-slate-500">
                    <tr>
                      <th class="px-4 py-3 text-left font-semibold">Browser / Device</th>
                      <th class="px-4 py-3 text-left font-semibold">Logged in at</th>
                      <th class="px-4 py-3 text-left font-semibold">Last active</th>
                      <th class="px-4 py-3 text-left font-semibold">Status</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-900/50">
                    <tr v-for="session in sessions" :key="session.session_id" class="text-slate-200">
                      <td class="px-4 py-3">
                        <p class="font-semibold text-slate-100">
                          {{ session.client_label || 'Unknown device' }}
                        </p>
                        <p class="text-xs text-slate-500">IP {{ session.ip_address ?? '—' }}</p>
                      </td>
                      <td class="px-4 py-3 text-slate-300">
                        {{ formatDate(session.created_at) }}
                      </td>
                      <td class="px-4 py-3 text-slate-300">
                        {{ formatRelative(session.last_seen_at) }}
                      </td>
                      <td class="px-4 py-3">
                        <span
                          class="rounded-full border border-emerald-400/40 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-emerald-200"
                        >
                          {{ session.status ?? 'active' }}
                        </span>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <p v-else class="mt-6 text-sm text-slate-400">
                No active sessions yet. Approve a login to create one.
              </p>
            </div>
          </section>

          <section
            id="link-device"
            class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 space-y-5"
          >
            <div>
              <h3 class="text-lg font-semibold text-indigo-300">Link a trusted device</h3>
              <p class="mt-1 text-sm text-slate-400">
                Generate a one-time code and enter it inside the Trustlogin Device App to enrol a new device.
              </p>
            </div>
            <p v-if="linkError" class="text-sm text-rose-300">{{ linkError }}</p>
            <div
              v-if="linkCode"
              class="space-y-3 rounded-2xl border border-indigo-500/40 bg-slate-950/70 p-5 text-center"
            >
              <p class="text-xs uppercase tracking-[0.4em] text-slate-500">Link code</p>
              <p class="text-4xl font-semibold tracking-[0.3em] text-slate-50">
                {{ formattedLinkCode }}
              </p>
              <p class="text-xs text-slate-400">
                Expires at {{ linkExpiryDisplay }}.
              </p>
            </div>
            <button
              class="w-full rounded-2xl border border-indigo-400/50 bg-indigo-500/20 px-4 py-3 text-sm font-semibold text-indigo-100 hover:bg-indigo-500/30 disabled:opacity-60"
              :disabled="linkLoading || !profile?.email"
              @click="generateLinkCode"
            >
              {{ linkLoading ? 'Generating code…' : linkCode ? 'Generate new code' : 'Generate link code' }}
            </button>
            <ul class="space-y-1 text-xs text-slate-500">
              <li>Codes are single-use and expire in about 10 minutes.</li>
              <li>Keep this window open until your device is linked.</li>
              <li>Enter your email, device name, and this code in the Trustlogin Device App.</li>
            </ul>
          </section>

          <section
            id="devices"
            class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <h3 class="text-lg font-semibold text-sky-200">Linked Devices</h3>
                <p class="text-sm text-slate-400">Trusted devices that can approve your sign-ins.</p>
              </div>
              <span class="rounded-full border border-slate-700/50 px-3 py-1 text-xs text-slate-400">
                {{ devices.length }} linked
              </span>
            </div>
            <p v-if="devicesError" class="mt-4 text-sm text-rose-300">{{ devicesError }}</p>
            <div
              v-if="devicesLoading"
              class="mt-4 rounded-2xl border border-slate-800 bg-slate-950/40 px-4 py-3 text-sm text-slate-400"
            >
              Loading linked devices…
            </div>
            <ul v-else class="mt-6 space-y-3">
              <li
                v-for="device in devices"
                :key="device.id"
                class="rounded-2xl border border-slate-800/70 bg-slate-950/60 p-4"
              >
                <p class="text-base font-semibold text-slate-100">{{ device.device_name }}</p>
                <p class="text-xs text-slate-400">
                  Linked {{ formatDate(device.linked_at) }}
                </p>
                <p class="text-xs font-semibold text-emerald-300">{{ device.status ?? 'active' }}</p>
              </li>
            </ul>
            <p v-if="!devices.length && !devicesLoading" class="mt-4 text-sm text-slate-400">
              No linked devices yet. Generate a link code to enrol your trusted device.
            </p>
          </section>

          <section
            id="safeguards"
            class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6"
          >
            <h3 class="text-lg font-semibold text-emerald-300">Key Safeguards</h3>
            <p class="mb-4 text-xs uppercase tracking-[0.2em] text-slate-500">
              Always-on protections
            </p>
            <div class="space-y-4">
              <article
                v-for="insight in safeguards"
                :key="insight.title"
                class="space-y-1 rounded-2xl border border-slate-800/70 bg-slate-950/70 p-4"
              >
                <p class="text-sm font-semibold text-slate-100">{{ insight.title }}</p>
                <p class="text-xs text-slate-400 leading-relaxed">{{ insight.detail }}</p>
              </article>
            </div>
          </section>

          <section
            id="news"
            class="rounded-3xl border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-950/60 p-6 lg:col-span-2"
          >
            <div class="flex flex-wrap items-center justify-between gap-4">
              <h3 class="text-lg font-semibold text-sky-300">Security &amp; Tech Headlines</h3>
              <p class="text-xs text-slate-400">Curated from trusted newsrooms</p>
            </div>
            <ul class="mt-6 grid gap-4 md:grid-cols-3">
              <li
                v-for="item in securityNews"
                :key="item.title"
                class="space-y-2 rounded-2xl border border-slate-800 bg-slate-950/50 p-4"
              >
                <p class="text-xs uppercase tracking-widest text-slate-500">{{ item.source }}</p>
                <p class="text-base font-semibold text-slate-100">{{ item.title }}</p>
                <p class="text-sm text-slate-400">{{ item.summary }}</p>
                <a
                  v-if="item.link"
                  :href="item.link"
                  target="_blank"
                  rel="noopener"
                  class="inline-flex items-center gap-1 text-xs font-semibold text-sky-300 hover:text-sky-200"
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
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { fetchProfile, fetchSessions, fetchDevices, startDeviceLink, logoutSession } from '../api';
import { clearToken } from '../token';

const router = useRouter();
const profile = ref(null);
const error = ref('');
const loading = ref(true);
const linkCode = ref('');
const linkExpiresAt = ref('');
const linkLoading = ref(false);
const linkError = ref('');
const sessions = ref([]);
const sessionsLoading = ref(true);
const sessionsError = ref('');
const devices = ref([]);
const devicesLoading = ref(true);
const devicesError = ref('');
const navItems = [
  { label: 'Overview', href: '#overview' },
  { label: 'Active Sessions', href: '#sessions' },
  { label: 'Linked Devices', href: '#devices' },
  { label: 'Link Device', href: '#link-device' },
  { label: 'Safeguards', href: '#safeguards' },
  { label: 'Headlines', href: '#news' }
];
const safeguards = [
  {
    title: 'Passkey protection',
    detail: 'Your devices use passkeys with hardware-backed encryption to keep logins phishing-resistant.'
  },
  {
    title: 'Session monitoring',
    detail: 'We alert you when sign-ins happen from unusual locations or browsers.'
  },
  {
    title: 'Data privacy',
    detail: 'Personal details stay encrypted at rest and are never shared with third parties.'
  }
];
const securityNews = [
  {
    title: 'Global agencies warn of credential phishing spikes',
    summary:
      'Interpol and CISA note a 46% rise in campaigns targeting password resets—passkeys remain a top mitigation.',
    source: 'CISA Brief',
    link: 'https://www.cisa.gov/news-events'
  },
  {
    title: 'AI helps defenders triage incidents faster',
    summary:
      'New tooling classifies alerts in seconds, freeing analysts to focus on threat hunting and proactive hardening.',
    source: 'CyberPulse Daily',
    link: 'https://www.cyberscoop.com/'
  },
  {
    title: 'Zero-trust adoption hits record highs',
    summary:
      'Enterprises accelerate device attestation and least-privilege access to secure hybrid workforces.',
    source: 'SecureWeek',
    link: 'https://www.darkreading.com/'
  }
];

const greetingName = computed(() => profile.value?.full_name ?? profile.value?.email ?? 'friend');

function handleUnauthorized(err) {
  if (err?.response?.status === 401) {
    clearToken();
    router.replace('/login');
    return true;
  }
  return false;
}

async function loadProfile() {
  try {
    profile.value = await fetchProfile();
    loading.value = false;
  } catch (err) {
    loading.value = false;
    if (handleUnauthorized(err)) {
      error.value = err?.response?.data?.message ?? 'Session expired.';
      return;
    }
    error.value = err?.response?.data?.message ?? 'Unable to load profile.';
  }
}

async function refreshSessions() {
  sessionsLoading.value = true;
  sessionsError.value = '';
  try {
    const result = await fetchSessions();
    sessions.value = result.sessions ?? [];
  } catch (err) {
    if (handleUnauthorized(err)) {
      return;
    }
    sessionsError.value = err?.response?.data?.message ?? 'Could not load sessions.';
  } finally {
    sessionsLoading.value = false;
  }
}

async function refreshDevices() {
  devicesLoading.value = true;
  devicesError.value = '';
  try {
    const result = await fetchDevices();
    devices.value = result.devices ?? [];
  } catch (err) {
    if (handleUnauthorized(err)) {
      return;
    }
    devicesError.value = err?.response?.data?.message ?? 'Could not load linked devices.';
  } finally {
    devicesLoading.value = false;
  }
}

async function signOut() {
  try {
    await logoutSession();
  } catch (err) {
    console.warn('Unable to revoke session on logout', err);
  } finally {
    clearToken();
    router.replace('/login');
  }
}

onMounted(() => {
  loadProfile();
  refreshSessions();
  refreshDevices();
});

async function generateLinkCode() {
  if (!profile.value?.email) {
    return;
  }
  linkError.value = '';
  linkLoading.value = true;
  try {
    const result = await startDeviceLink({ email: profile.value.email });
    linkCode.value = result.link_code;
    linkExpiresAt.value = result.expires_at;
  } catch (err) {
    linkError.value = err?.response?.data?.message ?? 'Could not generate a link code.';
  } finally {
    linkLoading.value = false;
  }
}

const formattedLinkCode = computed(() => {
  if (!linkCode.value) {
    return '';
  }
  const normalized = linkCode.value.trim();
  if (normalized.length <= 3) {
    return normalized;
  }
  return `${normalized.slice(0, 3)}-${normalized.slice(3)}`;
});

const linkExpiryDisplay = computed(() => {
  if (!linkExpiresAt.value) {
    return '—';
  }
  const expires = new Date(linkExpiresAt.value);
  if (Number.isNaN(expires.getTime())) {
    return '—';
  }
  const minutes = Math.max(0, Math.round((expires.getTime() - Date.now()) / 60000));
  return `${expires.toLocaleTimeString()} (${minutes} min left)`;
});

function formatDate(value) {
  if (!value) {
    return '—';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '—';
  }
  return parsed.toLocaleString();
}

function formatRelative(value) {
  if (!value) {
    return '—';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '—';
  }
  const diff = Date.now() - parsed.getTime();
  if (diff < 60000) {
    return 'just now';
  }
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) {
    return `${minutes} min ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours}h ago`;
  }
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
</script>
