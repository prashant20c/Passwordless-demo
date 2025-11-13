<template>
  <BrandCard>
    <div class="px-8 py-10 space-y-8">
      <template v-if="!registrationComplete">
        <div class="space-y-2 text-slate-200">
          <h2 class="text-3xl font-semibold">Create your Trustlogin account</h2>
          <p class="text-sm text-slate-400">
            Just your name and email—link devices later with a secure code.
          </p>
        </div>
        <form class="space-y-5" @submit.prevent="submit">
          <div class="space-y-2">
            <label class="block text-sm font-medium text-slate-300" for="full_name">Full name</label>
            <input
              id="full_name"
              v-model="form.full_name"
              type="text"
              required
              class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
            />
          </div>
          <div class="space-y-2">
            <label class="block text-sm font-medium text-slate-300" for="email">Email</label>
            <input
              id="email"
              v-model="form.email"
              type="email"
              required
              class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
            />
          </div>
          <p v-if="error" class="text-sm text-rose-300">{{ error }}</p>
          <button
            type="submit"
            class="w-full py-3 rounded-xl bg-amber-300 text-slate-900 font-semibold shadow hover:bg-amber-200"
            :disabled="loading"
          >
            {{ loading ? 'Creating account…' : 'Create account' }}
          </button>
        </form>
        <p class="text-sm text-slate-400 text-center">
          Already a member?
          <router-link to="/login" class="font-medium">Sign in without passwords</router-link>
        </p>
      </template>

      <template v-else>
        <div class="space-y-2 text-slate-200 text-center">
          <p class="text-xs uppercase tracking-[0.4em] text-emerald-300">Account ready</p>
          <h2 class="text-3xl font-semibold">Link your first device</h2>
          <p class="text-sm text-slate-400">
            Use this one-time code inside the Trustlogin Device App to finish enrolling <span class="font-semibold">{{ registeredEmail }}</span>.
          </p>
        </div>
        <div class="rounded-2xl border border-emerald-400/40 bg-slate-900/60 p-6 space-y-4 text-center text-slate-100">
          <p class="text-xs uppercase tracking-[0.4em] text-slate-500">Device link code</p>
          <p class="text-5xl font-semibold tracking-[0.3em]">{{ formattedLinkCode }}</p>
          <p class="text-xs text-slate-400">Expires at {{ linkExpiryDisplay }}</p>
          <p v-if="linkError" class="text-sm text-rose-300">{{ linkError }}</p>
          <button
            class="w-full rounded-xl border border-emerald-300/50 px-4 py-3 text-sm font-semibold text-emerald-100 hover:bg-emerald-400/20 disabled:opacity-60"
            :disabled="linkLoading"
            @click="regenerateLinkCode"
          >
            {{ linkLoading ? 'Refreshing…' : 'Generate new code' }}
          </button>
        </div>
        <ul class="text-xs text-slate-400 space-y-1">
          <li>Keep this page open while linking &mdash; codes expire in about 10 minutes.</li>
          <li>Open the Trustlogin Device App, enter your email, a device name, and this code.</li>
          <li>After your device links successfully you can close this window.</li>
        </ul>
        <button
          class="w-full rounded-xl bg-amber-300 text-slate-900 font-semibold shadow hover:bg-amber-200 py-3"
          @click="goToLogin"
        >
          Continue to login
        </button>
      </template>
    </div>
  </BrandCard>
</template>

<script setup>
import { computed, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import BrandCard from '../components/BrandCard.vue';
import { registerUser, startDeviceLink } from '../api';

const router = useRouter();
const loading = ref(false);
const error = ref('');
const form = reactive({
  full_name: '',
  email: ''
});
const registrationComplete = ref(false);
const registeredEmail = ref('');
const linkCode = ref('');
const linkExpiresAt = ref('');
const linkLoading = ref(false);
const linkError = ref('');

async function submit() {
  error.value = '';
  loading.value = true;
  try {
    await registerUser({ ...form });
    registrationComplete.value = true;
    registeredEmail.value = form.email;
    await regenerateLinkCode();
  } catch (err) {
    error.value = err?.response?.data?.message ?? 'Registration failed. Please try again.';
  } finally {
    loading.value = false;
  }
}

async function regenerateLinkCode() {
  if (!registeredEmail.value) {
    return;
  }
  linkError.value = '';
  linkLoading.value = true;
  try {
    const result = await startDeviceLink({ email: registeredEmail.value });
    linkCode.value = result.link_code;
    linkExpiresAt.value = result.expires_at;
  } catch (err) {
    linkError.value = err?.response?.data?.message ?? 'Unable to generate link code.';
  } finally {
    linkLoading.value = false;
  }
}

function goToLogin() {
  router.push('/login');
}

const formattedLinkCode = computed(() => {
  if (!linkCode.value) {
    return '000-000';
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
</script>
