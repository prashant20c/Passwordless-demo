<template>
  <BrandCard>
    <div class="px-8 py-10 space-y-6 text-slate-200">
      <div class="space-y-1">
        <h2 class="text-3xl font-semibold">Welcome back</h2>
        <p class="text-sm text-slate-400">The boutique is yours, {{ profile?.full_name ?? 'friend' }}.</p>
      </div>
      <p v-if="error" class="text-sm text-rose-300">{{ error }}</p>
      <div v-if="loading" class="rounded-2xl border border-slate-700 bg-slate-800/60 p-6 text-sm text-slate-300">
        Loading your boutique profile…
      </div>
      <div v-else class="rounded-2xl border border-slate-700 bg-slate-800/60 p-6 space-y-3">
        <h3 class="text-lg font-semibold text-amber-200">Account details</h3>
        <dl class="space-y-2 text-sm">
          <div class="flex justify-between">
            <dt class="text-slate-400">Full name</dt>
            <dd class="text-slate-100">{{ profile?.full_name }}</dd>
          </div>
          <div class="flex justify-between">
            <dt class="text-slate-400">Email</dt>
            <dd class="text-slate-100">{{ profile?.email }}</dd>
          </div>
        </dl>
      </div>
      <button
        class="w-full py-3 rounded-xl bg-slate-700 text-slate-100 font-medium hover:bg-slate-600"
        @click="signOut"
      >
        Sign out
      </button>
    </div>
  </BrandCard>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import BrandCard from '../components/BrandCard.vue';
import { fetchProfile } from '../api';
import { clearToken } from '../token';

const router = useRouter();
const profile = ref(null);
const error = ref('');
const loading = ref(true);

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
