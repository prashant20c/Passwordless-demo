<template>
  <BrandCard>
    <div class="px-8 py-10 space-y-8">
      <div class="space-y-2 text-slate-200">
        <h2 class="text-3xl font-semibold">Login without a password</h2>
        <p class="text-sm text-slate-400">Enter your email and approve the sign-in from your trusted device.</p>
      </div>
      <form class="space-y-5" @submit.prevent="startLogin">
        <div class="space-y-2">
          <label class="block text-sm font-medium text-slate-300" for="email">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            required
            class="w-full rounded-xl bg-slate-800/70 border border-slate-700 px-4 py-3 focus:outline-none focus:ring-2 focus:ring-amber-300"
          />
        </div>
        <p v-if="error" class="text-sm text-rose-300">{{ error }}</p>
        <button
          type="submit"
          class="w-full py-3 rounded-xl bg-amber-300 text-slate-900 font-semibold shadow hover:bg-amber-200 disabled:opacity-70"
          :disabled="loading"
        >
          {{ loading ? 'Waiting for approval…' : 'Login without password' }}
        </button>
      </form>
      <div v-if="loading" class="rounded-2xl bg-slate-800/60 border border-slate-700 px-5 py-4 space-y-2">
        <p class="text-sm text-slate-300 flex items-center gap-2">
          <span class="inline-flex h-3 w-3 animate-pulse rounded-full bg-amber-300"></span>
          Waiting for your device approval…
        </p>
        <p class="text-xs text-slate-500">Expires in {{ secondsRemaining }}s</p>
      </div>
      <p class="text-sm text-slate-400 text-center">
        New here?
        <router-link to="/register" class="font-medium">Create an account</router-link>
      </p>
    </div>
  </BrandCard>
</template>

<script setup>
import { onBeforeUnmount, ref } from 'vue';
import { useRouter } from 'vue-router';
import BrandCard from '../components/BrandCard.vue';
import { clearToken, saveToken } from '../token';
import { pollLoginStatus, requestLogin } from '../api';

const router = useRouter();
const email = ref('');
const loading = ref(false);
const error = ref('');
const loginId = ref('');
const secondsRemaining = ref(60);
let timer = null;
let poller = null;

clearToken();

async function startLogin() {
  if (loading.value) return;
  error.value = '';
  secondsRemaining.value = 60;
  try {
    loading.value = true;
    const { login_id } = await requestLogin({ email: email.value });
    loginId.value = login_id;
    startCountdown();
    startPolling();
  } catch (err) {
    loading.value = false;
    error.value = err?.response?.data?.message ?? 'Unable to request login. Try again soon.';
  }
}

function startCountdown() {
  clearInterval(timer);
  timer = setInterval(() => {
    secondsRemaining.value -= 1;
    if (secondsRemaining.value <= 0) {
      stopPolling();
      loading.value = false;
      error.value = 'Login request expired. Please try again.';
      clearInterval(timer);
    }
  }, 1000);
}

function startPolling() {
  clearTimers();
  poller = setInterval(async () => {
    try {
      const result = await pollLoginStatus(loginId.value);
      if (result.status === 'APPROVED' && result.token) {
        saveToken(result.token);
        stopPolling();
        router.push('/account');
      } else if (result.status === 'REJECTED' || result.status === 'EXPIRED') {
        error.value = result.status === 'REJECTED' ? 'Login rejected on device.' : 'Login expired.';
        stopPolling();
      }
    } catch (err) {
      console.error(err);
    }
  }, 2000);
}

function clearTimers() {
  if (poller) {
    clearInterval(poller);
    poller = null;
  }
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

function stopPolling() {
  loading.value = false;
  clearTimers();
}

onBeforeUnmount(() => {
  stopPolling();
});
</script>
